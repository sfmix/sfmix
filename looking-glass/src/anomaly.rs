//! Durable ND-anomaly event store with rollup/hysteresis.
//!
//! The live discovered-neighbor store ([`crate::discovered`]) sets a `conflict`
//! flag the instant a second MAC is heard for an IP — and never clears it. That
//! latch makes legitimate router migrations and transient bursts look like
//! permanent warnings. This store records each *new-MAC-on-an-existing-IP* event
//! as a discrete, queryable record instead, and folds repeated flaps within a
//! cooldown window into a single event with a rising `flap_count`. A thousand
//! flaps in a minute become one event, not a thousand.
//!
//! Backed by SQLite (WAL) so events survive restarts and can be browsed from the
//! portal. The poll loop writes via [`AnomalyStore::record_conflict`]; RPC
//! handlers read via [`AnomalyStore::list_events`] / [`AnomalyStore::get_event`].

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use rusqlite::{Connection, OptionalExtension};
use tracing::{info, warn};

use crate::structured::AnomalyEvent;

/// Build the anomaly store from the discovered-neighbors config, or `None` when
/// `anomaly_db` is unset (recording disabled) or the DB fails to open (logged).
pub fn open_from_config(
    cfg: &crate::config::DiscoveredNeighborsConfig,
) -> Option<std::sync::Arc<AnomalyStore>> {
    let path = cfg.anomaly_db.as_ref()?;
    match AnomalyStore::open(Path::new(path), cfg.anomaly_cooldown_secs) {
        Ok(s) => {
            info!("ND anomaly store opened at {path} (cooldown {}s)", cfg.anomaly_cooldown_secs);
            Some(std::sync::Arc::new(s))
        }
        Err(e) => {
            warn!("Failed to open ND anomaly store {path}: {e}; anomaly recording disabled");
            None
        }
    }
}

/// In-memory cooldown state for one IP with an open (un-expired) event.
struct OpenEvent {
    id: String,
    last_seen: DateTime<Utc>,
    flap_count: u64,
}

/// In-memory cooldown state for one MAC with an open sweep event. Carries the
/// accumulated claimed-IP set so a growing sweep rolls into one event.
struct OpenSweep {
    id: String,
    last_seen: DateTime<Utc>,
    flap_count: u64,
    ips: std::collections::HashSet<String>,
}

/// Maximum claimed IPs retained per sweep event (bounds row/JSON size against a
/// MAC blanketing a huge range). The cardinality signal is preserved well before
/// this — it only caps what we enumerate.
const MAX_CLAIMED_IPS: usize = 256;

/// Mutex-guarded interior: the SQLite connection plus the cooldown maps.
/// A single lock serializes the poll loop's writes against RPC reads — event
/// volume is low (one poll every ~60s), so this is simpler and adequate versus
/// juggling separate read/write connections.
struct Inner {
    conn: Connection,
    /// ip → currently-open `new_mac_on_ip` event, for O(1) cooldown decisions.
    open: HashMap<String, OpenEvent>,
    /// mac → currently-open `mac_claims_many_ips` (sweep) event.
    open_sweeps: HashMap<String, OpenSweep>,
}

/// Outcome of folding one conflict observation into the store.
#[derive(Debug, Clone)]
pub struct ConflictRecord {
    /// The event the observation was attributed to.
    pub event_id: String,
    /// True when a brand-new event was opened (vs. a flap rolled into an open
    /// one). Phase 2 uses this to decide whether to trigger a pcap snapshot.
    pub is_new: bool,
}

/// Durable anomaly event store.
pub struct AnomalyStore {
    inner: Mutex<Inner>,
    cooldown: Duration,
}

impl AnomalyStore {
    /// Open (creating if needed) the SQLite store at `path` and seed the
    /// in-memory cooldown map from any still-open events.
    pub fn open(path: &Path, cooldown_secs: u64) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating anomaly DB directory {}", parent.display()))?;
            }
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening anomaly DB {}", path.display()))?;
        Self::from_conn(conn, cooldown_secs)
    }

    /// Construct from an existing connection (used by `open` and tests).
    fn from_conn(conn: Connection, cooldown_secs: u64) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")
            .context("setting WAL mode")?;
        conn.pragma_update(None, "synchronous", "NORMAL").ok();
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS nd_events (
                id          TEXT PRIMARY KEY,
                ip          TEXT NOT NULL,
                family      TEXT NOT NULL,
                asn         INTEGER,
                tenant      TEXT,
                old_macs    TEXT NOT NULL,
                new_mac     TEXT NOT NULL,
                opened_at   TEXT NOT NULL,
                last_seen   TEXT NOT NULL,
                flap_count  INTEGER NOT NULL DEFAULT 1,
                evidence_id TEXT,
                closed      INTEGER NOT NULL DEFAULT 0,
                kind        TEXT NOT NULL DEFAULT 'new_mac_on_ip',
                claimed_ips TEXT,
                classification TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_nd_events_ip ON nd_events(ip);
            CREATE INDEX IF NOT EXISTS idx_nd_events_asn ON nd_events(asn);
            CREATE INDEX IF NOT EXISTS idx_nd_events_opened ON nd_events(opened_at);
            CREATE INDEX IF NOT EXISTS idx_nd_events_kind ON nd_events(kind);
            "#,
        )
        .context("initializing nd_events schema")?;

        // Additive column migrations for DBs created before a column existed. SQLite
        // has no `ADD COLUMN IF NOT EXISTS`, so we run each `ALTER` and tolerate the
        // "duplicate column name" error (column already present); anything else is a
        // real failure worth surfacing. Keep newly-added nullable columns in this
        // list so existing on-disk stores gain them on the next startup.
        for ddl in ["ALTER TABLE nd_events ADD COLUMN classification TEXT"] {
            match conn.execute(ddl, []) {
                Ok(_) => {}
                Err(e) if e.to_string().contains("duplicate column name") => {}
                Err(e) => return Err(e).with_context(|| format!("nd_events migration: {ddl}")),
            }
        }

        let cooldown = Duration::seconds(cooldown_secs as i64);

        // Seed the cooldown maps from events still within their cooldown window at
        // startup, so a restart keeps folding into / extending the same event
        // rather than opening a duplicate. Events whose window already lapsed are
        // not loaded (they read as closed); this also bounds the maps to recent
        // events rather than every never-superseded row ever written.
        let now = Utc::now();
        let mut open: HashMap<String, OpenEvent> = HashMap::new();
        let mut open_sweeps: HashMap<String, OpenSweep> = HashMap::new();
        {
            let mut stmt = conn
                .prepare(
                    "SELECT id, ip, last_seen, flap_count, kind, new_mac, claimed_ips
                     FROM nd_events WHERE closed = 0",
                )
                .context("preparing open-event seed query")?;
            let rows = stmt
                .query_map([], |row| {
                    let id: String = row.get(0)?;
                    let ip: String = row.get(1)?;
                    let last_seen: String = row.get(2)?;
                    let flap_count: i64 = row.get(3)?;
                    let kind: String = row.get(4)?;
                    let new_mac: String = row.get(5)?;
                    let claimed_ips: Option<String> = row.get(6)?;
                    Ok((id, ip, last_seen, flap_count, kind, new_mac, claimed_ips))
                })
                .context("seeding open events")?;
            for r in rows {
                let (id, ip, last_seen, flap_count, kind, new_mac, claimed_ips) =
                    r.context("reading open-event row")?;
                let last = match DateTime::parse_from_rfc3339(&last_seen) {
                    Ok(t) => t.with_timezone(&Utc),
                    Err(_) => continue,
                };
                if now - last > cooldown {
                    continue; // window already lapsed: leave it closed.
                }
                let flaps = flap_count.max(0) as u64;
                if kind == lg_types::structured::EVENT_KIND_MAC_SWEEP {
                    // Keyed on the offending MAC; restore the claimed-IP set.
                    let ips: std::collections::HashSet<String> = claimed_ips
                        .as_deref()
                        .and_then(|j| serde_json::from_str(j).ok())
                        .unwrap_or_default();
                    let replace = open_sweeps.get(&new_mac).is_none_or(|e| last > e.last_seen);
                    if replace {
                        open_sweeps.insert(new_mac, OpenSweep { id, last_seen: last, flap_count: flaps, ips });
                    }
                } else {
                    // Keep the most recently seen per-IP event.
                    let replace = open.get(&ip).is_none_or(|e| last > e.last_seen);
                    if replace {
                        open.insert(ip, OpenEvent { id, last_seen: last, flap_count: flaps });
                    }
                }
            }
        }

        Ok(Self {
            inner: Mutex::new(Inner { conn, open, open_sweeps }),
            cooldown,
        })
    }

    /// Record a new-MAC-on-an-existing-IP observation.
    ///
    /// Within the cooldown window of an open event for the same IP, this folds in
    /// as a flap (`flap_count += 1`, `last_flap` advanced). Otherwise it opens a
    /// fresh event (closing any prior one for that IP). Errors are logged and
    /// swallowed — anomaly bookkeeping must never break the poll loop.
    #[allow(clippy::too_many_arguments)] // each arg is a distinct facet of the conflict
    pub fn record_conflict(
        &self,
        ip: &str,
        family: &str,
        asn: Option<u32>,
        tenant: Option<&str>,
        old_macs: &[String],
        new_mac: &str,
        now: DateTime<Utc>,
    ) -> Option<ConflictRecord> {
        match self.record_conflict_inner(ip, family, asn, tenant, old_macs, new_mac, now) {
            Ok(r) => Some(r),
            Err(e) => {
                warn!("Failed to record ND anomaly for {ip} (new MAC {new_mac}): {e}");
                None
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record_conflict_inner(
        &self,
        ip: &str,
        family: &str,
        asn: Option<u32>,
        tenant: Option<&str>,
        old_macs: &[String],
        new_mac: &str,
        now: DateTime<Utc>,
    ) -> Result<ConflictRecord> {
        let now_str = now.to_rfc3339();
        let mut guard = self.inner.lock().unwrap();
        let Inner { conn, open, .. } = &mut *guard;

        // Flap: an open event for this IP still within cooldown of its last
        // sighting. A new distinct MAC bumps flap_count and extends the window.
        if let Some(ev) = open.get_mut(ip) {
            if now - ev.last_seen <= self.cooldown {
                ev.flap_count += 1;
                ev.last_seen = now;
                conn.execute(
                    "UPDATE nd_events SET flap_count = ?1, last_seen = ?2 WHERE id = ?3",
                    rusqlite::params![ev.flap_count as i64, now_str, ev.id],
                )
                .context("updating flap_count")?;
                return Ok(ConflictRecord { event_id: ev.id.clone(), is_new: false });
            }
        }

        // No open event, or the prior one expired: close the stale one and open a
        // fresh event for this IP.
        if let Some(prev) = open.remove(ip) {
            conn.execute("UPDATE nd_events SET closed = 1 WHERE id = ?1", rusqlite::params![prev.id])
                .context("closing expired event")?;
        }
        let id = uuid::Uuid::new_v4().to_string();
        let old_macs_json = serde_json::to_string(old_macs).context("serializing old_macs")?;
        conn.execute(
            "INSERT INTO nd_events
                (id, ip, family, asn, tenant, old_macs, new_mac, opened_at, last_seen, flap_count, evidence_id, closed, kind, claimed_ips)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, 1, NULL, 0, 'new_mac_on_ip', NULL)",
            rusqlite::params![id, ip, family, asn, tenant, old_macs_json, new_mac, now_str],
        )
        .context("inserting nd_event")?;
        open.insert(ip.to_string(), OpenEvent { id: id.clone(), last_seen: now, flap_count: 1 });
        Ok(ConflictRecord { event_id: id, is_new: true })
    }

    /// Record a `mac_claims_many_ips` (proxy-ARP / sweep) observation: a single
    /// MAC heard claiming several IPs in one poll. Rolls up keyed on the MAC, so a
    /// sweep that grows over successive polls is one event with an accumulating
    /// `claimed_ips` set rather than an event storm. Errors are logged and
    /// swallowed. Returns the event id and whether it was newly opened.
    ///
    /// `asn`/`tenant` attribute the sweep to the offending MAC's owning
    /// participant (resolved from NetBox assignments). `classification` refines
    /// what the sweep *is*: pass `Some("reflection")` when the claims are verbatim
    /// flood reflection (the frames preserved the true owner's MAC in their
    /// link-layer option). Classification is monotonic — once an open sweep is
    /// classified it is never downgraded by a later plain fold — and asn/tenant
    /// are filled in if the event was opened before they were known.
    #[allow(clippy::too_many_arguments)]
    pub fn record_mac_sweep(
        &self,
        mac: &str,
        family: &str,
        asn: Option<u32>,
        tenant: Option<&str>,
        claimed_ips: &[String],
        classification: Option<&str>,
        now: DateTime<Utc>,
    ) -> Option<ConflictRecord> {
        match self.record_mac_sweep_inner(mac, family, asn, tenant, claimed_ips, classification, now) {
            Ok(r) => Some(r),
            Err(e) => {
                warn!("Failed to record ND MAC-sweep for {mac}: {e}");
                None
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record_mac_sweep_inner(
        &self,
        mac: &str,
        family: &str,
        asn: Option<u32>,
        tenant: Option<&str>,
        claimed_ips: &[String],
        classification: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<ConflictRecord> {
        let now_str = now.to_rfc3339();
        let mut guard = self.inner.lock().unwrap();
        let Inner { conn, open_sweeps, .. } = &mut *guard;

        // Roll into the open sweep for this MAC if still within cooldown: union the
        // newly-claimed IPs, bump flap_count, extend the window. `COALESCE` upgrades
        // classification/asn/tenant if they were unset at open time without ever
        // clobbering a value already present.
        if let Some(sw) = open_sweeps.get_mut(mac) {
            if now - sw.last_seen <= self.cooldown {
                for ip in claimed_ips {
                    if sw.ips.len() >= MAX_CLAIMED_IPS {
                        break;
                    }
                    sw.ips.insert(ip.clone());
                }
                sw.flap_count += 1;
                sw.last_seen = now;
                let ips_json = serde_json::to_string(&sorted(&sw.ips)).context("serializing claimed_ips")?;
                conn.execute(
                    "UPDATE nd_events
                        SET flap_count = ?1, last_seen = ?2, claimed_ips = ?3,
                            asn = COALESCE(asn, ?4), tenant = COALESCE(tenant, ?5),
                            classification = COALESCE(classification, ?6)
                      WHERE id = ?7",
                    rusqlite::params![sw.flap_count as i64, now_str, ips_json, asn, tenant, classification, sw.id],
                )
                .context("updating sweep")?;
                return Ok(ConflictRecord { event_id: sw.id.clone(), is_new: false });
            }
        }

        // No open sweep (or it expired): close the stale one and open a fresh one.
        if let Some(prev) = open_sweeps.remove(mac) {
            conn.execute("UPDATE nd_events SET closed = 1 WHERE id = ?1", rusqlite::params![prev.id])
                .context("closing expired sweep")?;
        }
        let mut ips: std::collections::HashSet<String> = std::collections::HashSet::new();
        for ip in claimed_ips.iter().take(MAX_CLAIMED_IPS) {
            ips.insert(ip.clone());
        }
        let id = uuid::Uuid::new_v4().to_string();
        let ips_json = serde_json::to_string(&sorted(&ips)).context("serializing claimed_ips")?;
        conn.execute(
            "INSERT INTO nd_events
                (id, ip, family, asn, tenant, old_macs, new_mac, opened_at, last_seen, flap_count, evidence_id, closed, kind, claimed_ips, classification)
             VALUES (?1, '', ?2, ?3, ?4, '[]', ?5, ?6, ?6, 1, NULL, 0, 'mac_claims_many_ips', ?7, ?8)",
            rusqlite::params![id, family, asn, tenant, mac, now_str, ips_json, classification],
        )
        .context("inserting sweep event")?;
        open_sweeps.insert(mac.to_string(), OpenSweep { id: id.clone(), last_seen: now, flap_count: 1, ips });
        Ok(ConflictRecord { event_id: id, is_new: true })
    }

    /// The rollup/freshness window. Callers use it to decide which MAC sightings
    /// still count as "live" before calling [`touch_conflict`].
    pub fn cooldown(&self) -> Duration {
        self.cooldown
    }

    /// Extend the window of the open event for `ip` to `now`, when the conflict
    /// is still being heard but no *new* MAC arrived (so [`record_conflict`]
    /// wouldn't fire). Keeps a long-running conflict's event open for its true
    /// duration; it closes ~one cooldown after the conflict stops being heard.
    /// No-op when no event is currently open for the IP. Errors are logged and
    /// swallowed — anomaly bookkeeping must never break the poll loop.
    ///
    /// The caller must only invoke this while the conflict is *genuinely live* —
    /// i.e. ≥2 distinct MACs heard within [`cooldown`](Self::cooldown). Keying on
    /// freshness (not on the un-aged record) is what lets a migration's event
    /// close: once the old MAC's sightings age past the window, the conflict is
    /// no longer live, touches stop, and the event closes.
    pub fn touch_conflict(&self, ip: &str, now: DateTime<Utc>) {
        let mut guard = self.inner.lock().unwrap();
        let Inner { conn, open, .. } = &mut *guard;
        let Some(ev) = open.get_mut(ip) else { return };
        // Only advance forward, and only while still within the window.
        if now <= ev.last_seen || now - ev.last_seen > self.cooldown {
            return;
        }
        ev.last_seen = now;
        let id = ev.id.clone();
        if let Err(e) = conn.execute(
            "UPDATE nd_events SET last_seen = ?1 WHERE id = ?2",
            rusqlite::params![now.to_rfc3339(), id],
        ) {
            warn!("Failed to extend ND anomaly window for {ip}: {e}");
        }
    }

    /// Attach an evidence (pcap snapshot) id to an event. Used by Phase 2.
    pub fn set_evidence(&self, event_id: &str, evidence_id: &str) -> Result<()> {
        let guard = self.inner.lock().unwrap();
        guard
            .conn
            .execute(
                "UPDATE nd_events SET evidence_id = ?1 WHERE id = ?2",
                rusqlite::params![evidence_id, event_id],
            )
            .context("setting evidence_id")?;
        Ok(())
    }

    /// List events newest-first, optionally narrowed by ASN and/or IP, with
    /// limit/offset paging. `closed` is computed at read time so it reflects the
    /// current cooldown even for events whose row hasn't been re-touched.
    pub fn list_events(
        &self,
        asn: Option<u32>,
        ip: Option<&str>,
        limit: i64,
        offset: i64,
        now: DateTime<Utc>,
    ) -> Result<Vec<AnomalyEvent>> {
        let guard = self.inner.lock().unwrap();
        let mut sql = String::from(
            "SELECT id, ip, family, asn, tenant, old_macs, new_mac, opened_at, last_seen, flap_count, evidence_id, closed, kind, claimed_ips, classification
             FROM nd_events WHERE 1=1",
        );
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(asn) = asn {
            sql.push_str(" AND asn = ?");
            params.push(Box::new(asn));
        }
        if let Some(ip) = ip {
            sql.push_str(" AND ip = ?");
            params.push(Box::new(ip.to_string()));
        }
        sql.push_str(" ORDER BY opened_at DESC LIMIT ? OFFSET ?");
        params.push(Box::new(limit));
        params.push(Box::new(offset));

        let mut stmt = guard.conn.prepare(&sql).context("preparing list query")?;
        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let cooldown = self.cooldown;
        let rows = stmt
            .query_map(param_refs.as_slice(), |row| Ok(row_to_event(row, now, cooldown)))
            .context("querying events")?;
        let mut events = Vec::new();
        for r in rows {
            events.push(r.context("reading event row")??);
        }
        Ok(events)
    }

    /// Fetch a single event by id.
    pub fn get_event(&self, id: &str, now: DateTime<Utc>) -> Result<Option<AnomalyEvent>> {
        let guard = self.inner.lock().unwrap();
        let event = guard
            .conn
            .query_row(
                "SELECT id, ip, family, asn, tenant, old_macs, new_mac, opened_at, last_seen, flap_count, evidence_id, closed, kind, claimed_ips, classification
                 FROM nd_events WHERE id = ?1",
                rusqlite::params![id],
                |row| Ok(row_to_event(row, now, self.cooldown)),
            )
            .optional()
            .context("querying event by id")?;
        match event {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }
}

/// Map a row to an [`AnomalyEvent`]. `closed` is true when the row was explicitly
/// superseded by a newer event *or* its cooldown has elapsed with no further flaps
/// — so an event reads as closed once it stops accumulating, even if no later
/// conflict on the same IP has re-touched it. Returns the inner `Result` so
/// JSON/timestamp parse errors surface per-row.
fn row_to_event(row: &rusqlite::Row, now: DateTime<Utc>, cooldown: Duration) -> Result<AnomalyEvent> {
    let asn: Option<i64> = row.get(3)?;
    let old_macs_json: String = row.get(5)?;
    let last_seen: String = row.get(8)?;
    let flap_count: i64 = row.get(9)?;
    let closed_int: i64 = row.get(11)?;
    let kind: String = row.get(12)?;
    let claimed_ips_json: Option<String> = row.get(13)?;
    let classification: Option<String> = row.get(14)?;
    let old_macs: Vec<String> =
        serde_json::from_str(&old_macs_json).context("deserializing old_macs")?;
    let claimed_ips: Vec<String> = claimed_ips_json
        .as_deref()
        .map(|j| serde_json::from_str(j).context("deserializing claimed_ips"))
        .transpose()?
        .unwrap_or_default();
    let expired = DateTime::parse_from_rfc3339(&last_seen)
        .map(|t| now - t.with_timezone(&Utc) > cooldown)
        .unwrap_or(false);
    Ok(AnomalyEvent {
        id: row.get(0)?,
        kind,
        ip: row.get(1)?,
        family: row.get(2)?,
        asn: asn.map(|a| a as u32),
        tenant: row.get(4)?,
        old_macs,
        new_mac: row.get(6)?,
        claimed_ips,
        opened_at: row.get(7)?,
        last_seen,
        flap_count: flap_count.max(0) as u64,
        evidence_id: row.get(10)?,
        closed: closed_int != 0 || expired,
        classification,
    })
}

/// A stable, sorted Vec view of a string set (for deterministic JSON storage).
fn sorted(set: &std::collections::HashSet<String>) -> Vec<String> {
    let mut v: Vec<String> = set.iter().cloned().collect();
    v.sort();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn store(cooldown_secs: u64) -> AnomalyStore {
        AnomalyStore::from_conn(Connection::open_in_memory().unwrap(), cooldown_secs).unwrap()
    }

    #[test]
    fn first_conflict_opens_a_new_event() {
        let s = store(600);
        let r = s
            .record_conflict("10.0.0.1", "IPv4", Some(64500), Some("Acme"), &["aa:aa".into()], "bb:bb", at("2026-06-19T00:00:00Z"))
            .unwrap();
        assert!(r.is_new);
        let events = s.list_events(None, None, 100, 0, at("2026-06-19T00:00:00Z")).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].flap_count, 1);
        assert_eq!(events[0].old_macs, vec!["aa:aa".to_string()]);
        assert_eq!(events[0].new_mac, "bb:bb");
        assert!(!events[0].closed);
    }

    #[test]
    fn flaps_within_cooldown_roll_into_one_event() {
        let s = store(600);
        let base = at("2026-06-19T00:00:00Z");
        let first = s
            .record_conflict("10.0.0.1", "IPv4", Some(64500), Some("Acme"), &["aa:aa".into()], "bb:bb", base)
            .unwrap();
        // 999 more flaps, each well within the 600s window of the previous.
        for i in 1..1000 {
            let t = base + Duration::seconds(i);
            let r = s
                .record_conflict("10.0.0.1", "IPv4", Some(64500), Some("Acme"), &["aa:aa".into()], "cc:cc", t)
                .unwrap();
            assert!(!r.is_new, "flap {i} must not open a new event");
            assert_eq!(r.event_id, first.event_id);
        }
        let events = s.list_events(None, None, 100, 0, base).unwrap();
        assert_eq!(events.len(), 1, "1000 flaps must be one event");
        assert_eq!(events[0].flap_count, 1000);
    }

    #[test]
    fn flap_after_cooldown_opens_a_fresh_event() {
        let s = store(600);
        let base = at("2026-06-19T00:00:00Z");
        let first = s
            .record_conflict("10.0.0.1", "IPv4", Some(64500), Some("Acme"), &["aa:aa".into()], "bb:bb", base)
            .unwrap();
        // Past the cooldown: a new event opens, prior one is closed.
        let later = base + Duration::seconds(601);
        let second = s
            .record_conflict("10.0.0.1", "IPv4", Some(64500), Some("Acme"), &["aa:aa".into()], "bb:bb", later)
            .unwrap();
        assert!(second.is_new);
        assert_ne!(first.event_id, second.event_id);

        let events = s.list_events(None, None, 100, 0, later).unwrap();
        assert_eq!(events.len(), 2);
        // Newest first.
        assert_eq!(events[0].id, second.event_id);
        assert!(!events[0].closed);
        // The prior event was explicitly closed when the new one opened.
        let prior = s.get_event(&first.event_id, later).unwrap().unwrap();
        assert!(prior.closed);
    }

    #[test]
    fn distinct_ips_get_distinct_events() {
        let s = store(600);
        let t = at("2026-06-19T00:00:00Z");
        let a = s.record_conflict("10.0.0.1", "IPv4", None, None, &["aa:aa".into()], "bb:bb", t).unwrap();
        let b = s.record_conflict("10.0.0.2", "IPv4", None, None, &["aa:aa".into()], "bb:bb", t).unwrap();
        assert!(a.is_new && b.is_new);
        assert_ne!(a.event_id, b.event_id);
        assert_eq!(s.list_events(None, None, 100, 0, t).unwrap().len(), 2);
        // Filter by IP narrows correctly.
        assert_eq!(s.list_events(None, Some("10.0.0.2"), 100, 0, t).unwrap().len(), 1);
    }

    #[test]
    fn asn_filter_narrows_listing() {
        let s = store(600);
        let t = at("2026-06-19T00:00:00Z");
        s.record_conflict("10.0.0.1", "IPv4", Some(64500), Some("Acme"), &["aa:aa".into()], "bb:bb", t).unwrap();
        s.record_conflict("10.0.0.2", "IPv4", Some(64501), Some("Globex"), &["aa:aa".into()], "bb:bb", t).unwrap();
        let only = s.list_events(Some(64501), None, 100, 0, t).unwrap();
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].asn, Some(64501));
    }

    #[test]
    fn touch_extends_window_and_keeps_event_open_past_a_cooldown() {
        let s = store(600);
        let base = at("2026-06-19T00:00:00Z");
        let r = s
            .record_conflict("10.0.0.1", "IPv4", Some(64500), Some("Acme"), &["aa:aa".into()], "bb:bb", base)
            .unwrap();
        // Re-hearing the conflict every 60s (no new MAC) keeps extending the
        // window. Walk well past the 600s cooldown of the original open.
        for i in 1..=20 {
            s.touch_conflict("10.0.0.1", base + Duration::seconds(60 * i));
        }
        let end = base + Duration::seconds(60 * 20); // 20 min after open
        let events = s.list_events(None, None, 10, 0, end).unwrap();
        assert_eq!(events.len(), 1, "still one event");
        assert_eq!(events[0].flap_count, 1, "touch must not bump flap_count");
        assert_eq!(events[0].opened_at, base.to_rfc3339(), "window start is immutable");
        assert_eq!(events[0].last_seen, end.to_rfc3339(), "window end tracks last sighting");
        assert!(!events[0].closed, "event stays open while still heard");

        // Once it stops being heard, it closes ~one cooldown later.
        let quiet = end + Duration::seconds(601);
        let after = s.get_event(&r.event_id, quiet).unwrap().unwrap();
        assert!(after.closed, "event closes after the conflict goes quiet");
    }

    #[test]
    fn touch_is_a_noop_without_an_open_event() {
        let s = store(600);
        let t = at("2026-06-19T00:00:00Z");
        // No event open for this IP: touch must not create one.
        s.touch_conflict("10.0.0.9", t);
        assert!(s.list_events(None, None, 10, 0, t).unwrap().is_empty());
    }

    #[test]
    fn touch_does_not_resurrect_a_lapsed_event() {
        let s = store(600);
        let base = at("2026-06-19T00:00:00Z");
        s.record_conflict("10.0.0.1", "IPv4", None, None, &["aa:aa".into()], "bb:bb", base).unwrap();
        // A touch arriving after the window already lapsed must not extend it.
        let late = base + Duration::seconds(900);
        s.touch_conflict("10.0.0.1", late);
        let ev = &s.list_events(None, None, 10, 0, late).unwrap()[0];
        assert_eq!(ev.last_seen, base.to_rfc3339(), "lapsed window is not extended");
        assert!(ev.closed, "lapsed event stays closed");
    }

    #[test]
    fn mac_sweep_opens_and_rolls_up_growing_ip_set() {
        let s = store(600);
        let base = at("2026-06-19T00:00:00Z");
        let r1 = s
            .record_mac_sweep("0a:rogue", "", None, None, &["10.0.0.1".into(), "10.0.0.2".into()], None, base)
            .unwrap();
        assert!(r1.is_new);
        // More IPs claimed by the same MAC within cooldown → same event, grown set.
        let r2 = s
            .record_mac_sweep("0a:rogue", "", None, None, &["10.0.0.2".into(), "10.0.0.3".into()], None, base + Duration::seconds(60))
            .unwrap();
        assert!(!r2.is_new, "a growing sweep rolls into the open event");
        assert_eq!(r1.event_id, r2.event_id);

        let events = s.list_events(None, None, 10, 0, base + Duration::seconds(60)).unwrap();
        assert_eq!(events.len(), 1, "one rolling sweep event, not an event storm");
        let e = &events[0];
        assert_eq!(e.kind, lg_types::structured::EVENT_KIND_MAC_SWEEP);
        assert_eq!(e.new_mac, "0a:rogue");
        assert_eq!(e.flap_count, 2);
        assert_eq!(e.claimed_ips, vec!["10.0.0.1", "10.0.0.2", "10.0.0.3"], "claimed IPs accumulate (deduped, sorted)");
        assert!(e.ip.is_empty(), "sweep events have no single subject IP");
    }

    #[test]
    fn sweep_and_per_ip_events_coexist_distinctly() {
        let s = store(600);
        let t = at("2026-06-19T00:00:00Z");
        s.record_conflict("10.0.0.1", "IPv4", Some(64500), Some("Acme"), &["aa:aa".into()], "bb:bb", t).unwrap();
        s.record_mac_sweep("0a:rogue", "", None, None, &["10.0.0.5".into(), "10.0.0.6".into()], None, t).unwrap();
        let all = s.list_events(None, None, 10, 0, t).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all.iter().filter(|e| e.kind == lg_types::structured::EVENT_KIND_NEW_MAC).count(), 1);
        assert_eq!(all.iter().filter(|e| e.kind == lg_types::structured::EVENT_KIND_MAC_SWEEP).count(), 1);
    }

    #[test]
    fn reflection_sweep_records_classification_and_owner() {
        let s = store(600);
        let t = at("2026-06-19T00:00:00Z");
        s.record_mac_sweep(
            "0a:00:05:18:9d:49",
            "IPv6",
            Some(26415),
            Some("Verisign"),
            &["2001:db8::1".into(), "2001:db8::2".into()],
            Some(lg_types::structured::EVENT_CLASSIFICATION_REFLECTION),
            t,
        )
        .unwrap();
        let e = &s.list_events(None, None, 10, 0, t).unwrap()[0];
        assert_eq!(e.kind, lg_types::structured::EVENT_KIND_MAC_SWEEP);
        assert_eq!(e.classification.as_deref(), Some("reflection"));
        assert_eq!(e.asn, Some(26415), "attributed to the reflector's participant");
        assert_eq!(e.new_mac, "0a:00:05:18:9d:49");
    }

    #[test]
    fn classification_upgrades_but_never_downgrades() {
        let s = store(600);
        let base = at("2026-06-19T00:00:00Z");
        // Opens plain (no classification yet, owner unknown).
        s.record_mac_sweep("0a:rogue", "IPv6", None, None, &["2001:db8::1".into()], None, base).unwrap();
        // A later fold carries the reflection signal + resolved owner → upgrade.
        s.record_mac_sweep(
            "0a:rogue", "IPv6", Some(26415), Some("Verisign"), &["2001:db8::2".into()],
            Some("reflection"), base + Duration::seconds(60),
        )
        .unwrap();
        let e = &s.list_events(None, None, 10, 0, base + Duration::seconds(60)).unwrap()[0];
        assert_eq!(e.classification.as_deref(), Some("reflection"), "None → reflection upgrades");
        assert_eq!(e.asn, Some(26415), "asn filled in on the fold");
        // A subsequent plain fold must not clear the classification.
        s.record_mac_sweep("0a:rogue", "IPv6", None, None, &["2001:db8::3".into()], None, base + Duration::seconds(120)).unwrap();
        let e = &s.list_events(None, None, 10, 0, base + Duration::seconds(120)).unwrap()[0];
        assert_eq!(e.classification.as_deref(), Some("reflection"), "reflection is never downgraded");
        assert_eq!(e.asn, Some(26415), "resolved owner is retained");
    }

    #[test]
    fn migrates_a_pre_classification_db_and_reads_old_rows_as_unclassified() {
        // Build the *old* table shape by hand (no classification column) and seed a row.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"CREATE TABLE nd_events (
                id TEXT PRIMARY KEY, ip TEXT NOT NULL, family TEXT NOT NULL, asn INTEGER,
                tenant TEXT, old_macs TEXT NOT NULL, new_mac TEXT NOT NULL, opened_at TEXT NOT NULL,
                last_seen TEXT NOT NULL, flap_count INTEGER NOT NULL DEFAULT 1, evidence_id TEXT,
                closed INTEGER NOT NULL DEFAULT 0, kind TEXT NOT NULL DEFAULT 'new_mac_on_ip', claimed_ips TEXT
            );"#,
        )
        .unwrap();
        conn.execute(
            "INSERT INTO nd_events (id, ip, family, asn, tenant, old_macs, new_mac, opened_at, last_seen)
             VALUES ('old-1', '10.0.0.1', 'IPv4', NULL, NULL, '[\"aa:aa\"]', 'bb:bb', ?1, ?1)",
            rusqlite::params![at("2026-06-19T00:00:00Z").to_rfc3339()],
        )
        .unwrap();
        // from_conn must add the column without error and the old row must read back.
        let s = AnomalyStore::from_conn(conn, 600).unwrap();
        let ev = s.get_event("old-1", at("2026-06-19T00:00:00Z")).unwrap().unwrap();
        assert_eq!(ev.classification, None, "pre-migration rows read as unclassified");
        assert_eq!(ev.new_mac, "bb:bb");
    }

    #[test]
    fn set_evidence_links_a_snapshot() {
        let s = store(600);
        let t = at("2026-06-19T00:00:00Z");
        let r = s.record_conflict("10.0.0.1", "IPv4", None, None, &["aa:aa".into()], "bb:bb", t).unwrap();
        s.set_evidence(&r.event_id, "evid-123").unwrap();
        let ev = s.get_event(&r.event_id, t).unwrap().unwrap();
        assert_eq!(ev.evidence_id.as_deref(), Some("evid-123"));
    }
}
