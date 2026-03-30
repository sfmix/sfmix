use std::sync::Arc;
use tokio::sync::Semaphore;

/// Multi-dimensional rate limiter protecting network devices from query floods.
pub struct RateLimiter {
    /// Global concurrency semaphore
    global_concurrent: Arc<Semaphore>,
    /// Per-device concurrency limit
    per_device_concurrent: u32,
    /// Per-device commands per minute
    _per_device_cpm: u32,
    /// Per-user commands per minute
    _per_user_cpm: u32,
}

impl RateLimiter {
    pub fn new(
        global_max_concurrent: u32,
        per_device_concurrent: u32,
        per_device_cpm: u32,
        per_user_cpm: u32,
    ) -> Self {
        Self {
            global_concurrent: Arc::new(Semaphore::new(global_max_concurrent as usize)),
            per_device_concurrent,
            _per_device_cpm: per_device_cpm,
            _per_user_cpm: per_user_cpm,
        }
    }

    /// Acquire a permit to execute a command. Returns a guard that releases
    /// the permit when dropped.
    pub async fn acquire(&self, _device: &str, _user: &str) -> Result<RateLimitGuard, RateLimitError> {
        // TODO: check per-device and per-user token buckets

        let permit = self
            .global_concurrent
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| RateLimitError::Exhausted)?;

        Ok(RateLimitGuard { _permit: permit })
    }

    pub fn per_device_concurrent(&self) -> u32 {
        self.per_device_concurrent
    }
}

pub struct RateLimitGuard {
    _permit: tokio::sync::OwnedSemaphorePermit,
}

#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("rate limit exhausted, try again later")]
    Exhausted,
}
