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
/// - **Global concurrency**: at most N commands in flight across all devices/users
/// - **Per-user commands-per-minute**: sliding window, rejects if exceeded
pub struct RateLimiter {
    /// Global concurrency semaphore
    global_concurrent: Arc<Semaphore>,
    /// Per-user sliding window of command timestamps
    user_windows: DashMap<String, Mutex<VecDeque<Instant>>>,
    /// Max commands per user per 60-second window
    per_user_cpm: u32,
}

impl RateLimiter {
    pub fn new(
        global_max_concurrent: u32,
        per_user_cpm: u32,
    ) -> Self {
        Self {
            global_concurrent: Arc::new(Semaphore::new(global_max_concurrent as usize)),
            user_windows: DashMap::new(),
            per_user_cpm,
        }
    }

    /// Acquire a permit to execute a command.
    ///
    /// Checks per-user CPM first (cheap), then acquires a global concurrency
    /// permit. Returns a guard that releases the concurrency permit on drop.
    pub async fn acquire(&self, user: &str) -> Result<RateLimitGuard, RateLimitError> {
        // Per-user sliding window check
        self.check_user_cpm(user)?;

        // Global concurrency
        let permit = self
            .global_concurrent
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| RateLimitError::GlobalConcurrency)?;

        Ok(RateLimitGuard { _permit: permit })
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
    #[error("rate limit exceeded: max {limit} commands per minute")]
    UserCpm { limit: u32 },
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
        let rl = RateLimiter::new(10, 3); // 3 commands per minute

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
        let rl = RateLimiter::new(10, 2);

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
    async fn test_global_concurrency_limit() {
        let rl = RateLimiter::new(2, 100); // 2 concurrent, generous CPM

        // Hold two permits
        let _g1 = rl.acquire("user1").await.unwrap();
        let _g2 = rl.acquire("user2").await.unwrap();

        // Third should block — use try_acquire semantics via timeout
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            rl.acquire("user3"),
        )
        .await;

        // Should timeout (blocked on semaphore)
        assert!(result.is_err(), "should block when global limit reached");

        // Drop one permit
        drop(_g1);

        // Now should succeed
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            rl.acquire("user3"),
        )
        .await;
        assert!(result.is_ok(), "should succeed after permit released");
    }
}
