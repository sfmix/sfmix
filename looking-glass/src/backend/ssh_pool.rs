//! Per-device SSH connection pool.
//!
//! Network devices used to get a brand-new authenticated SSH connection for
//! *every* CLI command (connect → auth → exec → disconnect). A single logical
//! operation fans into several commands, and the background poll loop runs many
//! per device per cycle, so the connect/auth churn floods the device logs.
//!
//! This pool holds **one live connection per device** and runs each command on a
//! fresh *channel* over that connection — a channel is not a new connection, so
//! auth happens once per connection lifetime instead of once per command.
//!
//! ## Reuse model: serial per device
//! Each device has a `tokio::Mutex<Slot>`. A command holds that lock for its whole
//! duration (`run`), so commands to one device serialize over a single connection
//! and never open competing channels — the safest behaviour w.r.t. device
//! per-connection session limits, and correct even though the poll path bypasses
//! the user rate limiter. Streams (ping/traceroute) are the one exception: they
//! take the handle and release the lock immediately (`stream_handle`) so they don't
//! pin the device for up to a minute.
//!
//! ## Freshness model (CLI-level, not just TCP)
//! A connection is judged fresh by an actual CLI round-trip, never socket state
//! alone:
//!   1. `is_closed` — cheap negative fast-path (russh session-task / transport dead).
//!   2. Transport keepalives (configured on the connection) keep idle connections
//!      alive and trip `is_closed` on a dead peer; not a CLI command, so no command
//!      log noise.
//!   3. An **idle-gated CLI probe** — the authoritative signal. Real traffic bumps
//!      `last_activity`; the freshness task only probes connections idle past
//!      `probe_interval`, and uses `try_lock` so a busy connection (in use ⇒ fresh)
//!      is skipped. Under load, zero synthetic probes.
//!
//! The pool is generic over the connection type `H` with injectable
//! connect / is-closed / probe behaviours, so the pooling logic is unit-tested with
//! a fake connection and no real device (see tests). Production wires it to russh in
//! `ssh.rs` (`ConnectionPool` / `build_pool`).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use dashmap::DashMap;
use tokio::sync::Mutex;
use tracing::{debug, trace, warn};

use crate::config::DeviceConfig;

/// How often the freshness task wakes to check pooled connections.
const FRESHNESS_TICK: Duration = Duration::from_secs(30);

/// Outcome of a pooled operation, classifying whether a retry on a fresh
/// connection is warranted.
pub(crate) enum OpError {
    /// Connection-level failure (channel open / transport setup). The pooled
    /// connection is presumed dead: evict it and retry **once** on a fresh one.
    Retryable(anyhow::Error),
    /// Command-level failure (timeout, parse, …). The connection is fine; do not
    /// retry — that would re-run the command on the device and double-log.
    Fatal(anyhow::Error),
}

impl OpError {
    pub(crate) fn into_inner(self) -> anyhow::Error {
        match self {
            OpError::Retryable(e) | OpError::Fatal(e) => e,
        }
    }
}

type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Establishes (connects + authenticates) a connection to a device.
pub(crate) type ConnectFn<H> = Box<dyn Fn(DeviceConfig) -> BoxFut<Result<H>> + Send + Sync>;
/// Cheap, synchronous "is this connection definitely dead?" check.
pub(crate) type IsClosedFn<H> = Box<dyn Fn(&H) -> bool + Send + Sync>;
/// CLI freshness probe: run a tiny command over the connection, error if it fails.
pub(crate) type ProbeFn<H> = Box<dyn Fn(Arc<H>, DeviceConfig) -> BoxFut<Result<()>> + Send + Sync>;

struct PooledConn<H> {
    handle: Arc<H>,
    last_activity: Instant,
    config: DeviceConfig,
}

struct Slot<H> {
    conn: Option<PooledConn<H>>,
}

impl<H> Slot<H> {
    fn empty() -> Self {
        Slot { conn: None }
    }
}

/// A per-device pool of reusable SSH connections.
pub(crate) struct Pool<H> {
    conns: DashMap<String, Arc<Mutex<Slot<H>>>>,
    connect: ConnectFn<H>,
    is_closed: IsClosedFn<H>,
    probe: ProbeFn<H>,
    /// CLI idle freshness-probe interval. `Duration::ZERO` disables the probe.
    probe_interval: Duration,
    /// Optional hard cap on connection age (bounds session/key lifetime).
    /// `None` keeps a connection warm indefinitely while probes pass.
    max_idle: Option<Duration>,
}

impl<H: Send + Sync + 'static> Pool<H> {
    pub(crate) fn new(
        connect: ConnectFn<H>,
        is_closed: IsClosedFn<H>,
        probe: ProbeFn<H>,
        probe_interval: Duration,
        max_idle: Option<Duration>,
    ) -> Self {
        Pool {
            conns: DashMap::new(),
            connect,
            is_closed,
            probe,
            probe_interval,
            max_idle,
        }
    }

    /// Get-or-insert the per-device slot mutex, **dropping the DashMap shard guard
    /// before returning** so callers never `.await` while holding it (deadlock risk).
    fn slot_for(&self, name: &str) -> Arc<Mutex<Slot<H>>> {
        self.conns
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(Slot::empty())))
            .value()
            .clone()
    }

    /// Return a live handle for `config`, reusing the pooled connection when it is
    /// still fresh, otherwise (re)connecting. Caller must hold the slot lock.
    async fn get_or_connect(&self, slot: &mut Slot<H>, config: &DeviceConfig) -> Result<Arc<H>> {
        if let Some(c) = slot.conn.as_ref() {
            let stale = (self.is_closed)(&c.handle)
                || self
                    .max_idle
                    .is_some_and(|m| c.last_activity.elapsed() > m);
            if !stale {
                return Ok(c.handle.clone());
            }
            debug!(device = %config.name, "pooled SSH connection stale; reconnecting");
        }
        let handle = (self.connect)(config.clone()).await?;
        let handle = Arc::new(handle);
        slot.conn = Some(PooledConn {
            handle: handle.clone(),
            last_activity: Instant::now(),
            config: config.clone(),
        });
        Ok(handle)
    }

    fn touch(slot: &mut Slot<H>) {
        if let Some(c) = slot.conn.as_mut() {
            c.last_activity = Instant::now();
        }
    }

    /// Run a command on the device's connection (serial per device).
    ///
    /// Holds the per-device lock for the whole command. On a *connection-level*
    /// failure (`OpError::Retryable`) evicts the dead connection, reconnects, and
    /// retries the command **once**. Command-level failures (`OpError::Fatal`) are
    /// returned as-is without retry.
    ///
    /// When `reuse` is false the connection is **single-use**: it is dropped
    /// (closed) after the command rather than kept in the pool. This is required
    /// for devices that refuse a second channel on an existing SSH connection
    /// (e.g. Nokia SR-OS → `AdministrativelyProhibited`), where reuse would force a
    /// failed channel-open + reconnect on every subsequent command.
    pub(crate) async fn run<T, F, Fut>(&self, config: &DeviceConfig, reuse: bool, op: F) -> Result<T>
    where
        F: Fn(Arc<H>) -> Fut,
        Fut: Future<Output = Result<T, OpError>>,
    {
        let slot_arc = self.slot_for(&config.name);
        let mut slot = slot_arc.lock().await;

        let result = match self.get_or_connect(&mut slot, config).await {
            Err(e) => Err(e),
            Ok(handle) => match op(handle).await {
                Ok(v) => {
                    Self::touch(&mut slot);
                    Ok(v)
                }
                Err(OpError::Fatal(e)) => {
                    // The channel opened and we talked to the device; the connection
                    // itself is fine — keep it warm but surface the command error.
                    Self::touch(&mut slot);
                    Err(e)
                }
                Err(OpError::Retryable(e)) => {
                    debug!(device = %config.name, error = %e, "pooled connection failed mid-op; reconnecting and retrying once");
                    slot.conn = None;
                    match self.get_or_connect(&mut slot, config).await {
                        Ok(handle) => match op(handle).await {
                            Ok(v) => {
                                Self::touch(&mut slot);
                                Ok(v)
                            }
                            Err(e) => Err(e.into_inner()),
                        },
                        Err(e) => Err(e),
                    }
                }
            },
        };

        if !reuse {
            // Single-use: never pool this connection. Dropping the pool's Arc
            // closes it (the per-device lock guarantees only one such connection
            // to the device at a time).
            slot.conn = None;
        }
        result
    }

    /// Acquire a handle for a long-running stream and **release the slot lock**
    /// (so a 60s ping/traceroute doesn't pin the device). The caller owns the
    /// returned `Arc<H>` for the stream's lifetime, keeping the connection alive.
    pub(crate) async fn stream_handle(&self, config: &DeviceConfig, reuse: bool) -> Result<Arc<H>> {
        let slot_arc = self.slot_for(&config.name);
        let mut slot = slot_arc.lock().await;
        let handle = self.get_or_connect(&mut slot, config).await?;
        Self::touch(&mut slot);
        if !reuse {
            // Single-use: don't pool it. The stream owns the returned Arc and the
            // connection closes when the stream ends.
            slot.conn = None;
        }
        Ok(handle)
    }

    /// Evict the pooled connection for `name` only if it is still the exact handle
    /// `dead` (ptr-eq) — never evict a connection another task already replaced.
    pub(crate) async fn invalidate(&self, name: &str, dead: &Arc<H>) {
        let Some(slot_arc) = self.conns.get(name).map(|e| e.value().clone()) else {
            return;
        };
        let mut slot = slot_arc.lock().await;
        if let Some(c) = slot.conn.as_ref() {
            if Arc::ptr_eq(&c.handle, dead) {
                slot.conn = None;
            }
        }
    }

    /// Spawn the background freshness/keepalive task.
    pub(crate) fn spawn_freshness_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(FRESHNESS_TICK);
            tick.tick().await; // consume the immediate first tick
            loop {
                tick.tick().await;
                self.freshness_round().await;
            }
        });
    }

    /// One pass over pooled connections: evict dead ones, and probe idle ones to
    /// verify CLI freshness (keeping them warm). Skips connections in active use.
    async fn freshness_round(&self) {
        // Snapshot the slot Arcs first so we never hold a DashMap shard guard
        // across the probe `.await`.
        let slots: Vec<Arc<Mutex<Slot<H>>>> =
            self.conns.iter().map(|e| e.value().clone()).collect();

        for slot_arc in slots {
            // If we can't lock it, it's in use — therefore fresh. Skip.
            let Ok(mut slot) = slot_arc.try_lock() else {
                continue;
            };
            // Extract what the probe needs, ending the borrow before any `.await`.
            let (handle, config, closed, idle) = match slot.conn.as_ref() {
                Some(c) => (
                    c.handle.clone(),
                    c.config.clone(),
                    (self.is_closed)(&c.handle),
                    c.last_activity.elapsed(),
                ),
                None => continue,
            };

            if closed {
                slot.conn = None;
                continue;
            }
            if self.probe_interval.is_zero() || idle < self.probe_interval {
                continue;
            }

            match (self.probe)(handle, config).await {
                Ok(()) => {
                    trace!("SSH freshness probe ok");
                    Self::touch(&mut slot);
                }
                Err(e) => {
                    warn!(error = %e, "SSH freshness probe failed; evicting pooled connection");
                    slot.conn = None;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use crate::config::{DeviceAuthMethod, Platform};

    /// A fake connection: tracks closed-ness; identity via Arc pointer.
    struct FakeConn {
        closed: AtomicBool,
    }

    impl FakeConn {
        fn new() -> Self {
            FakeConn {
                closed: AtomicBool::new(false),
            }
        }
    }

    /// Shared test counters / switches captured by the injected closures.
    #[derive(Clone, Default)]
    struct Harness {
        connects: Arc<AtomicUsize>,
        probes: Arc<AtomicUsize>,
        probe_fails: Arc<AtomicBool>,
        connect_fails: Arc<AtomicBool>,
    }

    fn device(name: &str) -> DeviceConfig {
        DeviceConfig {
            name: name.to_string(),
            platform: Platform::AristaEos,
            host: "127.0.0.1".to_string(),
            port: 22,
            username: "test".to_string(),
            auth_method: DeviceAuthMethod::SshKey,
            ssh_key: None,
            host_key_fingerprint: None,
            command_timeout_secs: 15,
        }
    }

    fn build(h: &Harness, probe_interval: Duration, max_idle: Option<Duration>) -> Pool<FakeConn> {
        let hc = h.clone();
        let connect: ConnectFn<FakeConn> = Box::new(move |_cfg| {
            let hc = hc.clone();
            Box::pin(async move {
                hc.connects.fetch_add(1, Ordering::SeqCst);
                if hc.connect_fails.load(Ordering::SeqCst) {
                    anyhow::bail!("connect failed (test)");
                }
                Ok(FakeConn::new())
            })
        });
        let is_closed: IsClosedFn<FakeConn> =
            Box::new(|c: &FakeConn| c.closed.load(Ordering::SeqCst));
        let hp = h.clone();
        let probe: ProbeFn<FakeConn> = Box::new(move |_conn, _cfg| {
            let hp = hp.clone();
            Box::pin(async move {
                hp.probes.fetch_add(1, Ordering::SeqCst);
                if hp.probe_fails.load(Ordering::SeqCst) {
                    anyhow::bail!("probe failed (test)");
                }
                Ok(())
            })
        });
        Pool::new(connect, is_closed, probe, probe_interval, max_idle)
    }

    async fn ok_op(_h: Arc<FakeConn>) -> Result<(), OpError> {
        Ok(())
    }

    fn slot_has_conn(pool: &Pool<FakeConn>, name: &str) -> bool {
        pool.conns
            .get(name)
            .map(|e| e.value().clone())
            .and_then(|m| m.try_lock().ok().map(|s| s.conn.is_some()))
            .unwrap_or(false)
    }

    #[tokio::test]
    async fn reuses_one_connection_across_commands() {
        let h = Harness::default();
        let pool = build(&h, Duration::ZERO, None);
        let dev = device("sw1");
        for _ in 0..5 {
            pool.run(&dev, true, ok_op).await.unwrap();
        }
        assert_eq!(h.connects.load(Ordering::SeqCst), 1, "should connect once");
    }

    #[tokio::test]
    async fn single_use_does_not_pool_connection() {
        // reuse=false (e.g. Nokia SR-OS): each command must get a fresh
        // connection and never leave one pooled, so a second command reconnects.
        let h = Harness::default();
        let pool = build(&h, Duration::ZERO, None);
        let dev = device("sr1");
        pool.run(&dev, false, ok_op).await.unwrap();
        assert!(!slot_has_conn(&pool, "sr1"), "single-use conn must not be pooled");
        pool.run(&dev, false, ok_op).await.unwrap();
        assert_eq!(
            h.connects.load(Ordering::SeqCst),
            2,
            "each single-use command connects fresh (no reuse)"
        );
    }

    #[tokio::test]
    async fn concurrent_cold_start_connects_once() {
        let h = Harness::default();
        let pool = Arc::new(build(&h, Duration::ZERO, None));
        let dev = device("sw1");
        let op = |_c: Arc<FakeConn>| async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok::<(), OpError>(())
        };
        let (a, b) = tokio::join!(pool.run(&dev, true, op), pool.run(&dev, true, op));
        a.unwrap();
        b.unwrap();
        assert_eq!(
            h.connects.load(Ordering::SeqCst),
            1,
            "serial per-device lock should dedupe the cold start"
        );
    }

    #[tokio::test]
    async fn reconnects_when_closed() {
        let h = Harness::default();
        let pool = build(&h, Duration::ZERO, None);
        let dev = device("sw1");
        pool.run(&dev, true, ok_op).await.unwrap();
        assert_eq!(h.connects.load(Ordering::SeqCst), 1);
        // Mark the pooled connection closed → next run must reconnect.
        {
            let slot = pool.conns.get("sw1").unwrap().value().clone();
            let s = slot.lock().await;
            s.conn.as_ref().unwrap().handle.closed.store(true, Ordering::SeqCst);
        }
        pool.run(&dev, true, ok_op).await.unwrap();
        assert_eq!(h.connects.load(Ordering::SeqCst), 2, "should reconnect");
    }

    #[tokio::test]
    async fn retryable_error_reconnects_and_retries_once() {
        let h = Harness::default();
        let pool = build(&h, Duration::ZERO, None);
        let dev = device("sw1");
        let attempts = Arc::new(AtomicUsize::new(0));
        let a = attempts.clone();
        let op = move |_c: Arc<FakeConn>| {
            let a = a.clone();
            async move {
                let n = a.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    Err(OpError::Retryable(anyhow::anyhow!("dead channel")))
                } else {
                    Ok(())
                }
            }
        };
        pool.run(&dev, true, op).await.unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 2, "op runs twice");
        assert_eq!(h.connects.load(Ordering::SeqCst), 2, "reconnects once");
    }

    #[tokio::test]
    async fn fatal_error_does_not_retry() {
        let h = Harness::default();
        let pool = build(&h, Duration::ZERO, None);
        let dev = device("sw1");
        let attempts = Arc::new(AtomicUsize::new(0));
        let a = attempts.clone();
        let op = move |_c: Arc<FakeConn>| {
            let a = a.clone();
            async move {
                a.fetch_add(1, Ordering::SeqCst);
                Err::<(), OpError>(OpError::Fatal(anyhow::anyhow!("command timed out")))
            }
        };
        let res = pool.run(&dev, true, op).await;
        assert!(res.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 1, "no retry on fatal");
        assert_eq!(h.connects.load(Ordering::SeqCst), 1, "no reconnect on fatal");
    }

    #[tokio::test]
    async fn idle_connection_is_probed_and_kept() {
        let h = Harness::default();
        let pool = build(&h, Duration::from_millis(1), None);
        let dev = device("sw1");
        pool.run(&dev, true, ok_op).await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        pool.freshness_round().await;
        assert_eq!(h.probes.load(Ordering::SeqCst), 1, "idle conn probed");
        assert!(slot_has_conn(&pool, "sw1"), "passing probe keeps the conn");
    }

    #[tokio::test]
    async fn failing_probe_evicts_connection() {
        let h = Harness::default();
        let pool = build(&h, Duration::from_millis(1), None);
        let dev = device("sw1");
        pool.run(&dev, true, ok_op).await.unwrap();
        h.probe_fails.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(5)).await;
        pool.freshness_round().await;
        assert_eq!(h.probes.load(Ordering::SeqCst), 1);
        assert!(!slot_has_conn(&pool, "sw1"), "failing probe evicts the conn");
    }

    #[tokio::test]
    async fn busy_connection_is_not_probed() {
        let h = Harness::default();
        let pool = build(&h, Duration::from_millis(1), None);
        let dev = device("sw1");
        pool.run(&dev, true, ok_op).await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        // Hold the slot lock → freshness round must skip (in use ⇒ fresh).
        let slot = pool.conns.get("sw1").unwrap().value().clone();
        let _guard = slot.lock().await;
        pool.freshness_round().await;
        assert_eq!(h.probes.load(Ordering::SeqCst), 0, "busy conn not probed");
    }

    #[tokio::test]
    async fn recent_activity_suppresses_probe() {
        let h = Harness::default();
        // Large interval: connection is not yet idle past it.
        let pool = build(&h, Duration::from_secs(3600), None);
        let dev = device("sw1");
        pool.run(&dev, true, ok_op).await.unwrap();
        pool.freshness_round().await;
        assert_eq!(h.probes.load(Ordering::SeqCst), 0, "fresh traffic suppresses probe");
    }

    #[tokio::test]
    async fn invalidate_is_ptr_eq_guarded() {
        let h = Harness::default();
        let pool = build(&h, Duration::ZERO, None);
        let dev = device("sw1");
        pool.run(&dev, true, ok_op).await.unwrap();

        // A stale/foreign Arc must not evict the live connection.
        let foreign = Arc::new(FakeConn::new());
        pool.invalidate("sw1", &foreign).await;
        assert!(slot_has_conn(&pool, "sw1"), "foreign Arc must not evict");

        // The live Arc evicts.
        let live = {
            let slot = pool.conns.get("sw1").unwrap().value().clone();
            let s = slot.lock().await;
            s.conn.as_ref().unwrap().handle.clone()
        };
        pool.invalidate("sw1", &live).await;
        assert!(!slot_has_conn(&pool, "sw1"), "live Arc evicts");
    }

    #[tokio::test]
    async fn max_idle_forces_reconnect() {
        let h = Harness::default();
        let pool = build(&h, Duration::ZERO, Some(Duration::from_millis(1)));
        let dev = device("sw1");
        pool.run(&dev, true, ok_op).await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        pool.run(&dev, true, ok_op).await.unwrap();
        assert_eq!(
            h.connects.load(Ordering::SeqCst),
            2,
            "exceeding max_idle forces a reconnect"
        );
    }
}
