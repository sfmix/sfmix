use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use tokio::sync::{Mutex, Semaphore};

/// Convert an IP address to a rate-limit key based on its network prefix.
///
/// IPv4: /24 (e.g. "net:192.0.2.0/24")
/// IPv6: /56 (e.g. "net:2001:db8:abcd:ab00::/56")
///
/// This prevents users from rotating through IPs within the same allocation
/// to bypass per-user rate limits.
pub fn ip_to_rate_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!("net:{}.{}.{}.0/24", octets[0], octets[1], octets[2])
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            // /56 = first 3.5 segments; zero out the low 8 bits of segment [3]
            format!(
                "net:{:x}:{:x}:{:x}:{:x}::/56",
                segments[0],
                segments[1],
                segments[2],
                segments[3] & 0xff00
            )
        }
    }
}

/// Multi-dimensional rate limiter protecting network devices from query floods.
///
/// Enforces:
/// - **Global concurrency**: at most N commands in flight across all devices/users (rejects immediately)
/// - **Global commands-per-minute**: sliding window across all users
/// - **Per-user commands-per-minute**: sliding window, rejects if exceeded
pub struct RateLimiter {
    /// Global concurrency semaphore
    global_concurrent: Arc<Semaphore>,
    /// Global sliding window of command timestamps
    global_window: Mutex<VecDeque<Instant>>,
    /// Max commands globally per 60-second window
    global_cpm: u32,
    /// Per-user sliding window of command timestamps
    user_windows: DashMap<String, Mutex<VecDeque<Instant>>>,
    /// Max commands per user per 60-second window
    per_user_cpm: u32,
}

impl RateLimiter {
    pub fn new(
        global_max_concurrent: u32,
        global_cpm: u32,
        per_user_cpm: u32,
    ) -> Self {
        Self {
            global_concurrent: Arc::new(Semaphore::new(global_max_concurrent as usize)),
            global_window: Mutex::new(VecDeque::new()),
            global_cpm,
            user_windows: DashMap::new(),
            per_user_cpm,
        }
    }

    /// Acquire a permit to execute a command.
    ///
    /// Checks per-user CPM first (cheap), then global CPM, then tries to
    /// acquire a global concurrency permit. Rejects immediately if any
    /// limit is exceeded (never blocks/queues).
    pub async fn acquire(&self, user: &str) -> Result<RateLimitGuard, RateLimitError> {
        // Per-user sliding window check
        self.check_user_cpm(user)?;

        // Global CPM sliding window check
        self.check_global_cpm().await?;

        // Global concurrency — reject immediately if full
        let permit = self
            .global_concurrent
            .clone()
            .try_acquire_owned()
            .map_err(|_| RateLimitError::GlobalConcurrency)?;

        Ok(RateLimitGuard { _permit: permit })
    }

    /// Check and record a command against the global sliding window.
    async fn check_global_cpm(&self) -> Result<(), RateLimitError> {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(60);
        let mut timestamps = self.global_window.lock().await;

        while timestamps.front().map_or(false, |t| now.duration_since(*t) > window) {
            timestamps.pop_front();
        }

        if timestamps.len() >= self.global_cpm as usize {
            return Err(RateLimitError::GlobalCpm {
                limit: self.global_cpm,
            });
        }

        timestamps.push_back(now);
        Ok(())
    }

    /// Check and record a command for the user's sliding window.
    fn check_user_cpm(&self, user: &str) -> Result<(), RateLimitError> {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(60);

        let entry = self
            .user_windows
            .entry(user.to_string())
            .or_insert_with(|| Mutex::new(VecDeque::new()));

        // Use try_lock — contention here means the same user has concurrent
        // requests, which is fine; if we can't lock, just allow it through
        // (the global semaphore still protects the devices).
        if let Ok(mut timestamps) = entry.value().try_lock() {
            // Evict timestamps older than the window
            while timestamps.front().map_or(false, |t| now.duration_since(*t) > window) {
                timestamps.pop_front();
            }

            if timestamps.len() >= self.per_user_cpm as usize {
                return Err(RateLimitError::UserCpm {
                    limit: self.per_user_cpm,
                });
            }

            timestamps.push_back(now);
        }

        Ok(())
    }
}

pub struct RateLimitGuard {
    _permit: tokio::sync::OwnedSemaphorePermit,
}

#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("global concurrency limit reached, try again later")]
    GlobalConcurrency,
    #[error("global rate limit exceeded: max {limit} commands per minute")]
    GlobalCpm { limit: u32 },
    #[error("rate limit exceeded: max {limit} commands per minute")]
    UserCpm { limit: u32 },
}

/// Per-device rate limiter enforcing both concurrency and commands-per-minute
/// for each backend network device.
pub struct DeviceRateLimiter {
    /// Per-device concurrency semaphores
    semaphores: DashMap<String, Arc<Semaphore>>,
    /// Per-device sliding window of command timestamps
    device_windows: DashMap<String, Mutex<VecDeque<Instant>>>,
    /// Max concurrent commands per device
    max_concurrent: u32,
    /// Max commands per device per 60-second window
    cpm: u32,
}

impl DeviceRateLimiter {
    pub fn new(device_names: &[&str], max_concurrent: u32, cpm: u32) -> Self {
        let semaphores = DashMap::new();
        let device_windows = DashMap::new();
        for name in device_names {
            semaphores.insert(name.to_string(), Arc::new(Semaphore::new(max_concurrent as usize)));
            device_windows.insert(name.to_string(), Mutex::new(VecDeque::new()));
        }
        Self {
            semaphores,
            device_windows,
            max_concurrent,
            cpm,
        }
    }

    /// Try to acquire a permit for a specific device. Rejects immediately if
    /// the device's CPM or concurrency limit is reached.
    pub async fn try_acquire(&self, device: &str) -> Result<DevicePermit, DeviceRateLimitError> {
        // CPM check first (cheap)
        self.check_device_cpm(device).await?;

        // Concurrency — reject immediately
        let sem = self
            .semaphores
            .get(device)
            .ok_or_else(|| DeviceRateLimitError::UnknownDevice(device.to_string()))?
            .clone();

        let permit = sem
            .try_acquire_owned()
            .map_err(|_| DeviceRateLimitError::DeviceBusy(device.to_string()))?;

        Ok(DevicePermit { _permit: permit })
    }

    async fn check_device_cpm(&self, device: &str) -> Result<(), DeviceRateLimitError> {
        let entry = self
            .device_windows
            .get(device)
            .ok_or_else(|| DeviceRateLimitError::UnknownDevice(device.to_string()))?;

        let now = Instant::now();
        let window = std::time::Duration::from_secs(60);
        let mut timestamps = entry.value().lock().await;

        while timestamps.front().map_or(false, |t| now.duration_since(*t) > window) {
            timestamps.pop_front();
        }

        if timestamps.len() >= self.cpm as usize {
            return Err(DeviceRateLimitError::DeviceCpm {
                device: device.to_string(),
                limit: self.cpm,
            });
        }

        timestamps.push_back(now);
        Ok(())
    }

    #[allow(dead_code)]
    pub fn max_concurrent(&self) -> u32 {
        self.max_concurrent
    }
}

pub struct DevicePermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
}

#[derive(Debug, thiserror::Error)]
pub enum DeviceRateLimitError {
    #[error("device {0} is busy, try again later")]
    DeviceBusy(String),
    #[error("device {device} rate limit exceeded: max {limit} commands per minute")]
    DeviceCpm { device: String, limit: u32 },
    #[error("unknown device: {0}")]
    UnknownDevice(String),
}

// ---------------------------------------------------------------------------
// Connection-level protection (frontend layer)
// ---------------------------------------------------------------------------

/// Tracks active frontend connections and enforces global and per-source limits.
///
/// Used by telnet, SSH, and MCP frontends to reject connections before they
/// consume backend resources.
pub struct ConnectionTracker {
    /// Global max connections semaphore
    global: Arc<Semaphore>,
    /// Per-source (IP prefix) semaphores
    per_source: DashMap<String, Arc<Semaphore>>,
    /// Max connections per source
    max_per_source: u32,
    /// Idle timeout for persistent connections (telnet, SSH)
    pub idle_timeout: std::time::Duration,
}

impl ConnectionTracker {
    pub fn new(
        max_connections: u32,
        max_connections_per_source: u32,
        idle_timeout_secs: u64,
    ) -> Self {
        Self {
            global: Arc::new(Semaphore::new(max_connections as usize)),
            per_source: DashMap::new(),
            max_per_source: max_connections_per_source,
            idle_timeout: std::time::Duration::from_secs(idle_timeout_secs),
        }
    }

    /// Try to admit a new connection from the given source key.
    /// Returns a guard that releases both permits on drop.
    pub fn try_admit(&self, source_key: &str) -> Result<ConnectionGuard, ConnectionLimitError> {
        // Global limit
        let global_permit = self
            .global
            .clone()
            .try_acquire_owned()
            .map_err(|_| ConnectionLimitError::GlobalLimit)?;

        // Per-source limit
        let source_sem = self
            .per_source
            .entry(source_key.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(self.max_per_source as usize)))
            .clone();

        let source_permit = source_sem
            .try_acquire_owned()
            .map_err(|_| ConnectionLimitError::PerSourceLimit(source_key.to_string()))?;

        Ok(ConnectionGuard {
            _global_permit: global_permit,
            _source_permit: source_permit,
        })
    }
}

pub struct ConnectionGuard {
    _global_permit: tokio::sync::OwnedSemaphorePermit,
    _source_permit: tokio::sync::OwnedSemaphorePermit,
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectionLimitError {
    #[error("too many connections, try again later")]
    GlobalLimit,
    #[error("too many connections from your network ({0}), try again later")]
    PerSourceLimit(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_ipv4_rate_key_groups_by_slash24() {
        // Two IPs in the same /24 should produce the same key
        let a = ip_to_rate_key(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        let b = ip_to_rate_key(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254)));
        assert_eq!(a, b);
        assert_eq!(a, "net:192.0.2.0/24");
    }

    #[test]
    fn test_ipv4_rate_key_different_slash24() {
        let a = ip_to_rate_key(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        let b = ip_to_rate_key(IpAddr::V4(Ipv4Addr::new(192, 0, 3, 1)));
        assert_ne!(a, b);
    }

    #[test]
    fn test_ipv6_rate_key_groups_by_slash56() {
        // Two IPs in the same /56 should produce the same key
        let a = ip_to_rate_key(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0xab00, 0, 0, 0, 1)));
        let b = ip_to_rate_key(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0xabff, 0xffff, 0xffff, 0xffff, 0xffff)));
        assert_eq!(a, b);
        assert_eq!(a, "net:2001:db8:abcd:ab00::/56");
    }

    #[test]
    fn test_ipv6_rate_key_different_slash56() {
        let a = ip_to_rate_key(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0xab00, 0, 0, 0, 1)));
        let b = ip_to_rate_key(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0xac00, 0, 0, 0, 1)));
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn test_per_user_cpm_enforced() {
        let rl = RateLimiter::new(10, 1000, 3); // 3 commands per minute

        // First 3 should succeed
        for i in 0..3 {
            assert!(rl.acquire("alice").await.is_ok(), "request {i} should succeed");
        }

        // 4th should be rejected
        let result = rl.acquire("alice").await;
        assert!(matches!(result, Err(RateLimitError::UserCpm { limit: 3 })));
    }

    #[tokio::test]
    async fn test_per_user_cpm_independent_users() {
        let rl = RateLimiter::new(10, 1000, 2);

        // Alice uses her quota
        assert!(rl.acquire("alice").await.is_ok());
        assert!(rl.acquire("alice").await.is_ok());
        assert!(rl.acquire("alice").await.is_err());

        // Bob should still be fine
        assert!(rl.acquire("bob").await.is_ok());
        assert!(rl.acquire("bob").await.is_ok());
        assert!(rl.acquire("bob").await.is_err());
    }

    #[tokio::test]
    async fn test_global_concurrency_rejects_immediately() {
        let rl = RateLimiter::new(2, 1000, 100); // 2 concurrent, generous CPM

        // Hold two permits
        let _g1 = rl.acquire("user1").await.unwrap();
        let _g2 = rl.acquire("user2").await.unwrap();

        // Third should be rejected immediately (not block)
        let result = rl.acquire("user3").await;
        assert!(
            matches!(result, Err(RateLimitError::GlobalConcurrency)),
            "should reject immediately when global limit reached"
        );

        // Drop one permit
        drop(_g1);

        // Now should succeed
        let result = rl.acquire("user3").await;
        assert!(result.is_ok(), "should succeed after permit released");
    }

    #[tokio::test]
    async fn test_global_cpm_enforced() {
        let rl = RateLimiter::new(100, 3, 100); // generous concurrency, 3 global CPM

        // First 3 should succeed
        for i in 0..3 {
            assert!(rl.acquire(&format!("user{i}")).await.is_ok(), "request {i} should succeed");
        }

        // 4th should be rejected by global CPM
        let result = rl.acquire("user99").await;
        assert!(
            matches!(result, Err(RateLimitError::GlobalCpm { limit: 3 })),
            "should reject when global CPM exceeded"
        );
    }

    // --- DeviceRateLimiter tests ---

    #[tokio::test]
    async fn test_device_concurrency_rejects() {
        let drl = DeviceRateLimiter::new(&["sw1"], 1, 100);

        let _p1 = drl.try_acquire("sw1").await.unwrap();
        let result = drl.try_acquire("sw1").await;
        assert!(
            matches!(result, Err(DeviceRateLimitError::DeviceBusy(_))),
            "should reject when device concurrency full"
        );

        drop(_p1);
        assert!(drl.try_acquire("sw1").await.is_ok(), "should succeed after permit released");
    }

    #[tokio::test]
    async fn test_device_cpm_rejects() {
        let drl = DeviceRateLimiter::new(&["sw1"], 10, 2);

        assert!(drl.try_acquire("sw1").await.is_ok());
        assert!(drl.try_acquire("sw1").await.is_ok());

        let result = drl.try_acquire("sw1").await;
        assert!(
            matches!(result, Err(DeviceRateLimitError::DeviceCpm { .. })),
            "should reject when device CPM exceeded"
        );
    }

    #[tokio::test]
    async fn test_device_unknown_device() {
        let drl = DeviceRateLimiter::new(&["sw1"], 2, 100);
        let result = drl.try_acquire("sw99").await;
        assert!(matches!(result, Err(DeviceRateLimitError::UnknownDevice(_))));
    }

    // --- ConnectionTracker tests ---

    #[test]
    fn test_connection_tracker_global_cap() {
        let ct = ConnectionTracker::new(2, 10, 300);

        let _g1 = ct.try_admit("src1").unwrap();
        let _g2 = ct.try_admit("src2").unwrap();

        let result = ct.try_admit("src3");
        assert!(
            matches!(result, Err(ConnectionLimitError::GlobalLimit)),
            "should reject at global cap"
        );

        drop(_g1);
        assert!(ct.try_admit("src3").is_ok(), "should admit after guard dropped");
    }

    #[test]
    fn test_connection_tracker_per_source_cap() {
        let ct = ConnectionTracker::new(100, 2, 300);

        let _g1 = ct.try_admit("src1").unwrap();
        let _g2 = ct.try_admit("src1").unwrap();

        let result = ct.try_admit("src1");
        assert!(
            matches!(result, Err(ConnectionLimitError::PerSourceLimit(_))),
            "should reject at per-source cap"
        );

        // Different source should still work
        assert!(ct.try_admit("src2").is_ok());

        drop(_g1);
        assert!(ct.try_admit("src1").is_ok(), "should admit after guard dropped");
    }

    #[test]
    fn test_connection_guard_releases_on_drop() {
        let ct = ConnectionTracker::new(1, 1, 300);

        {
            let _g = ct.try_admit("src1").unwrap();
            assert!(ct.try_admit("src1").is_err(), "both limits should be full");
        }
        // Guard dropped
        assert!(ct.try_admit("src1").is_ok(), "should admit after guard dropped");
    }
}
