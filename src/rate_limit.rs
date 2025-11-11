use crate::config::RateLimitConfig;
use crate::core::{SecurityError, SecurityResult};
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// High-performance token bucket rate limiter
pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: Arc<DashMap<String, TokenBucket>>,
    global_counter: Arc<AtomicU64>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: Arc::new(DashMap::new()),
            global_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Check if a request is allowed
    pub async fn check(&self, identifier: &str) -> SecurityResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Get or create bucket for this identifier
        let bucket = self.buckets.entry(identifier.to_string()).or_insert_with(|| {
            TokenBucket::new(
                self.config.requests_per_window,
                self.config.burst_size,
                self.config.window_duration,
            )
        });

        if bucket.consume() {
            self.global_counter.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            let retry_after = bucket.time_until_refill();
            Err(SecurityError::RateLimitExceeded { retry_after })
        }
    }

    /// Get current rate limit statistics
    pub fn stats(&self) -> RateLimitStats {
        RateLimitStats {
            total_requests: self.global_counter.load(Ordering::Relaxed),
            active_buckets: self.buckets.len(),
        }
    }

    /// Clean up old buckets (call periodically)
    pub fn cleanup_old_buckets(&self) {
        self.buckets.retain(|_, bucket| !bucket.is_expired());
    }
}

/// Token bucket implementation for rate limiting
struct TokenBucket {
    tokens: parking_lot::Mutex<f64>,
    capacity: f64,
    refill_rate: f64, // tokens per second
    last_refill: parking_lot::Mutex<Instant>,
    window: Duration,
}

impl TokenBucket {
    fn new(requests: u32, burst: u32, window: Duration) -> Self {
        let capacity = burst as f64;
        let refill_rate = requests as f64 / window.as_secs_f64();

        Self {
            tokens: parking_lot::Mutex::new(capacity),
            capacity,
            refill_rate,
            last_refill: parking_lot::Mutex::new(Instant::now()),
            window,
        }
    }

    fn consume(&self) -> bool {
        self.refill();
        
        let mut tokens = self.tokens.lock();
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn refill(&self) {
        let now = Instant::now();
        let mut last_refill = self.last_refill.lock();
        let elapsed = now.duration_since(*last_refill).as_secs_f64();

        if elapsed > 0.0 {
            let mut tokens = self.tokens.lock();
            let new_tokens = elapsed * self.refill_rate;
            *tokens = (*tokens + new_tokens).min(self.capacity);
            *last_refill = now;
        }
    }

    fn time_until_refill(&self) -> u64 {
        let tokens = self.tokens.lock();
        let tokens_needed = 1.0 - *tokens;
        if tokens_needed <= 0.0 {
            return 0;
        }
        
        let seconds = (tokens_needed / self.refill_rate).ceil() as u64;
        seconds.max(1)
    }

    fn is_expired(&self) -> bool {
        let last_refill = self.last_refill.lock();
        Instant::now().duration_since(*last_refill) > self.window * 10
    }
}

/// Rate limit statistics
#[derive(Debug, Clone)]
pub struct RateLimitStats {
    pub total_requests: u64,
    pub active_buckets: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_allows_within_limit() {
        let config = RateLimitConfig {
            enabled: true,
            requests_per_window: 10,
            window_duration: Duration::from_secs(1),
            burst_size: 10,
            per_ip: true,
            per_user: false,
            adaptive: false,
        };

        let limiter = RateLimiter::new(config);

        // Should allow first 10 requests
        for _ in 0..10 {
            assert!(limiter.check("test-ip").await.is_ok());
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_blocks_over_limit() {
        let config = RateLimitConfig {
            enabled: true,
            requests_per_window: 5,
            window_duration: Duration::from_secs(60),
            burst_size: 5,
            per_ip: true,
            per_user: false,
            adaptive: false,
        };

        let limiter = RateLimiter::new(config);

        // Should allow first 5 requests
        for _ in 0..5 {
            assert!(limiter.check("test-ip").await.is_ok());
        }

        // 6th request should be blocked
        assert!(limiter.check("test-ip").await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_refills_over_time() {
        let config = RateLimitConfig {
            enabled: true,
            requests_per_window: 10,
            window_duration: Duration::from_secs(1),
            burst_size: 5,
            per_ip: true,
            per_user: false,
            adaptive: false,
        };

        let limiter = RateLimiter::new(config);

        // Consume all tokens
        for _ in 0..5 {
            assert!(limiter.check("test-ip").await.is_ok());
        }

        // Should be blocked
        assert!(limiter.check("test-ip").await.is_err());

        // Wait for refill
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Should allow more requests
        assert!(limiter.check("test-ip").await.is_ok());
    }
}
