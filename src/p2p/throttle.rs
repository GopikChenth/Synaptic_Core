//! Bandwidth Throttling and Token-Bucket Rate Limiting for P2P QUIC Block Exchange.
//!
//! Provides dynamic, token-bucket based rate limiting for inbound (download)
//! and outbound (upload) transfers, configurable in KiB/s.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::debug;

/// Internal state for a Token Bucket rate limiter.
#[derive(Debug)]
struct TokenBucketState {
    /// Configured rate limit in KiB/s (0 = unlimited).
    limit_kib: u64,
    /// Rate limit in bytes per second.
    rate_bytes_per_sec: f64,
    /// Maximum burst capacity in bytes.
    burst_capacity: f64,
    /// Currently available token balance in bytes.
    tokens: f64,
    /// Time when tokens were last replenished or when debt will be satisfied.
    last_replenish: tokio::time::Instant,
}

/// Asynchronous Token Bucket rate limiter for upload and download bandwidth management.
///
/// Limits transfer rates to a configurable number of KiB/s (1 KiB = 1024 bytes).
/// If the bucket is exhausted, calls to [`RateLimiter::acquire`] sleep dynamically
/// until enough tokens have accumulated.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    state: Arc<Mutex<TokenBucketState>>,
}

impl RateLimiter {
    /// Creates a new `RateLimiter` with the given rate limit in KiB/s.
    /// Setting `limit_kib_per_sec` to `0` disables throttling (unlimited bandwidth).
    ///
    /// Burst capacity defaults to at least 1 second worth of bandwidth or 64 KiB,
    /// whichever is larger.
    pub fn new(limit_kib_per_sec: u64) -> Self {
        let rate_bytes = (limit_kib_per_sec as f64) * 1024.0;
        let burst = if limit_kib_per_sec == 0 {
            0.0
        } else {
            rate_bytes.max(64.0 * 1024.0)
        };

        Self {
            state: Arc::new(Mutex::new(TokenBucketState {
                limit_kib: limit_kib_per_sec,
                rate_bytes_per_sec: rate_bytes,
                burst_capacity: burst,
                tokens: burst,
                last_replenish: tokio::time::Instant::now(),
            })),
        }
    }

    /// Creates a rate limiter with a custom burst capacity in bytes.
    pub fn with_burst(limit_kib_per_sec: u64, burst_bytes: usize) -> Self {
        let rate_bytes = (limit_kib_per_sec as f64) * 1024.0;
        let burst = burst_bytes as f64;

        Self {
            state: Arc::new(Mutex::new(TokenBucketState {
                limit_kib: limit_kib_per_sec,
                rate_bytes_per_sec: rate_bytes,
                burst_capacity: burst,
                tokens: burst,
                last_replenish: tokio::time::Instant::now(),
            })),
        }
    }

    /// Creates an unlimited rate limiter (zero delay on acquisitions).
    pub fn unlimited() -> Self {
        Self::new(0)
    }

    /// Returns the currently configured rate limit in KiB/s (0 = unlimited).
    pub async fn limit_kib(&self) -> u64 {
        self.state.lock().await.limit_kib
    }

    /// Updates the bandwidth limit in KiB/s dynamically at runtime.
    pub async fn set_rate_limit(&self, limit_kib_per_sec: u64) {
        let mut state = self.state.lock().await;
        let now = tokio::time::Instant::now();
        state.limit_kib = limit_kib_per_sec;

        if limit_kib_per_sec == 0 {
            state.rate_bytes_per_sec = 0.0;
            state.burst_capacity = 0.0;
            state.tokens = 0.0;
            state.last_replenish = now;
        } else {
            let new_rate = (limit_kib_per_sec as f64) * 1024.0;
            let new_burst = new_rate.max(64.0 * 1024.0);

            if state.rate_bytes_per_sec > 0.0 && state.last_replenish > now {
                // Adjust remaining debt time to the new rate
                let remaining_debt_bytes =
                    (state.last_replenish - now).as_secs_f64() * state.rate_bytes_per_sec;
                let adjusted_wait = remaining_debt_bytes / new_rate;
                state.last_replenish = now + Duration::from_secs_f64(adjusted_wait);
            } else {
                state.last_replenish = now;
            }

            state.rate_bytes_per_sec = new_rate;
            state.burst_capacity = new_burst;
            state.tokens = state.tokens.min(new_burst);
        }
        debug!("Bandwidth rate limit updated to {} KiB/s", limit_kib_per_sec);
    }

    /// Returns the current number of available tokens in bytes.
    pub async fn available_tokens(&self) -> usize {
        let state = self.state.lock().await;
        if state.limit_kib == 0 {
            return usize::MAX;
        }
        let now = tokio::time::Instant::now();
        if now >= state.last_replenish {
            let elapsed = (now - state.last_replenish).as_secs_f64();
            let added = elapsed * state.rate_bytes_per_sec;
            let tokens = (state.tokens + added).min(state.burst_capacity);
            tokens as usize
        } else {
            0
        }
    }

    /// Attempts to acquire `bytes` tokens without blocking.
    /// Returns `true` if tokens were successfully acquired, or `false` if the bucket was exhausted.
    pub async fn try_acquire(&self, bytes: usize) -> bool {
        if bytes == 0 {
            return true;
        }

        let mut state = self.state.lock().await;
        if state.limit_kib == 0 {
            return true;
        }

        let now = tokio::time::Instant::now();
        if now < state.last_replenish {
            return false;
        }

        let elapsed = (now - state.last_replenish).as_secs_f64();
        let max_cap = state.burst_capacity.max(bytes as f64);
        state.tokens = (state.tokens + elapsed * state.rate_bytes_per_sec).min(max_cap);
        state.last_replenish = now;

        if state.tokens >= bytes as f64 {
            state.tokens -= bytes as f64;
            true
        } else {
            false
        }
    }

    /// Asynchronously acquires `bytes` tokens from the bucket.
    ///
    /// If the token bucket is exhausted or has insufficient tokens, this method
    /// dynamically sleeps for the exact time required for tokens to replenish.
    pub async fn acquire(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }

        let sleep_duration = {
            let mut state = self.state.lock().await;
            if state.limit_kib == 0 {
                return;
            }

            let now = tokio::time::Instant::now();

            if now >= state.last_replenish {
                let elapsed = (now - state.last_replenish).as_secs_f64();
                let max_cap = state.burst_capacity.max(bytes as f64);
                state.tokens = (state.tokens + elapsed * state.rate_bytes_per_sec).min(max_cap);
                state.last_replenish = now;

                if state.tokens >= bytes as f64 {
                    state.tokens -= bytes as f64;
                    Duration::ZERO
                } else {
                    let deficit = (bytes as f64) - state.tokens;
                    state.tokens = 0.0;
                    let wait_secs = deficit / state.rate_bytes_per_sec;
                    let wait_dur = Duration::from_secs_f64(wait_secs);
                    state.last_replenish = now + wait_dur;
                    wait_dur
                }
            } else {
                // Bucket is already committed into the future for prior acquisitions
                let debt_wait = state.last_replenish.duration_since(now);
                let add_wait_secs = (bytes as f64) / state.rate_bytes_per_sec;
                let add_wait_dur = Duration::from_secs_f64(add_wait_secs);
                let total_wait = debt_wait + add_wait_dur;
                state.last_replenish += add_wait_dur;
                total_wait
            }
        };

        if !sleep_duration.is_zero() {
            tokio::time::sleep(sleep_duration).await;
        }
    }
}

/// Paired rate limiter managing independent upload and download bandwidth quotas.
#[derive(Debug, Clone)]
pub struct BandwidthLimiter {
    pub upload: Arc<RateLimiter>,
    pub download: Arc<RateLimiter>,
}

impl BandwidthLimiter {
    /// Creates a new `BandwidthLimiter` with upload and download limits in KiB/s.
    pub fn new(upload_kib_per_sec: u64, download_kib_per_sec: u64) -> Self {
        Self {
            upload: Arc::new(RateLimiter::new(upload_kib_per_sec)),
            download: Arc::new(RateLimiter::new(download_kib_per_sec)),
        }
    }

    /// Creates a new `BandwidthLimiter` with custom burst capacities in bytes.
    pub fn with_burst(
        upload_kib_per_sec: u64,
        upload_burst_bytes: usize,
        download_kib_per_sec: u64,
        download_burst_bytes: usize,
    ) -> Self {
        Self {
            upload: Arc::new(RateLimiter::with_burst(upload_kib_per_sec, upload_burst_bytes)),
            download: Arc::new(RateLimiter::with_burst(download_kib_per_sec, download_burst_bytes)),
        }
    }

    /// Creates an unthrottled bandwidth limiter.
    pub fn unlimited() -> Self {
        Self {
            upload: Arc::new(RateLimiter::unlimited()),
            download: Arc::new(RateLimiter::unlimited()),
        }
    }

    /// Acquires tokens for an outgoing upload transfer.
    pub async fn acquire_upload(&self, bytes: usize) {
        self.upload.acquire(bytes).await;
    }

    /// Acquires tokens for an incoming download transfer.
    pub async fn acquire_download(&self, bytes: usize) {
        self.download.acquire(bytes).await;
    }

    /// Dynamically sets the upload limit in KiB/s.
    pub async fn set_upload_limit(&self, limit_kib_per_sec: u64) {
        self.upload.set_rate_limit(limit_kib_per_sec).await;
    }

    /// Dynamically sets the download limit in KiB/s.
    pub async fn set_download_limit(&self, limit_kib_per_sec: u64) {
        self.download.set_rate_limit(limit_kib_per_sec).await;
    }

    /// Returns the current upload limit in KiB/s.
    pub async fn upload_limit_kib(&self) -> u64 {
        self.upload.limit_kib().await
    }

    /// Returns the current download limit in KiB/s.
    pub async fn download_limit_kib(&self) -> u64 {
        self.download.limit_kib().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_approx_duration(actual: Duration, expected: Duration, tolerance: Duration) {
        let diff = if actual >= expected {
            actual - expected
        } else {
            expected - actual
        };
        assert!(
            diff <= tolerance,
            "actual {:?} was not within {:?} of expected {:?}",
            actual,
            tolerance,
            expected
        );
    }

    #[tokio::test]
    async fn test_unlimited_rate_limiter() {
        let limiter = RateLimiter::unlimited();
        assert_eq!(limiter.limit_kib().await, 0);

        // Acquiring large amounts of data should not block or wait
        let start = tokio::time::Instant::now();
        limiter.acquire(10 * 1024 * 1024).await;
        let elapsed = start.elapsed();
        assert!(elapsed < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn test_rate_limiter_dynamic_sleep() {
        tokio::time::pause();

        // 10 KiB/s with zero initial burst
        let limiter = RateLimiter::with_burst(10, 0);
        assert_eq!(limiter.limit_kib().await, 10);

        // Acquiring 5 KiB (5120 bytes) at 10 KiB/s should sleep for ~500ms
        let start = tokio::time::Instant::now();
        limiter.acquire(5120).await;
        let elapsed = start.elapsed();
        assert_approx_duration(elapsed, Duration::from_millis(500), Duration::from_millis(10));

        // Acquiring another 5 KiB should take another ~500ms
        let start2 = tokio::time::Instant::now();
        limiter.acquire(5120).await;
        let elapsed2 = start2.elapsed();
        assert_approx_duration(elapsed2, Duration::from_millis(500), Duration::from_millis(10));
    }

    #[tokio::test]
    async fn test_rate_limiter_burst_consumption() {
        tokio::time::pause();

        // 10 KiB/s with 10 KiB burst
        let limiter = RateLimiter::with_burst(10, 10240);

        // Initial 10 KiB should be served immediately from burst tokens
        let start = tokio::time::Instant::now();
        limiter.acquire(10240).await;
        assert_eq!(start.elapsed(), Duration::ZERO);

        // Subsequent 10 KiB must sleep for 1 second
        let start2 = tokio::time::Instant::now();
        limiter.acquire(10240).await;
        assert_approx_duration(start2.elapsed(), Duration::from_secs(1), Duration::from_millis(10));
    }

    #[tokio::test]
    async fn test_concurrent_acquisitions() {
        tokio::time::pause();

        // 10 KiB/s, 0 burst
        let limiter = Arc::new(RateLimiter::with_burst(10, 0));
        let start = tokio::time::Instant::now();

        // Spawn 4 concurrent tasks, each acquiring 2560 bytes (2.5 KiB)
        // Total 10 KiB -> should take ~1 second in aggregate
        let mut handles = Vec::new();
        for _ in 0..4 {
            let l = limiter.clone();
            handles.push(tokio::spawn(async move {
                l.acquire(2560).await;
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        let elapsed = start.elapsed();
        assert_approx_duration(elapsed, Duration::from_secs(1), Duration::from_millis(20));
    }

    #[tokio::test]
    async fn test_dynamic_reconfiguration() {
        tokio::time::pause();

        let limiter = RateLimiter::with_burst(10, 0);
        let start = tokio::time::Instant::now();
        limiter.acquire(5120).await; // 500ms at 10 KiB/s
        assert_approx_duration(start.elapsed(), Duration::from_millis(500), Duration::from_millis(10));

        // Double speed to 20 KiB/s
        limiter.set_rate_limit(20).await;
        assert_eq!(limiter.limit_kib().await, 20);

        let start2 = tokio::time::Instant::now();
        limiter.acquire(5120).await; // 250ms at 20 KiB/s
        assert_approx_duration(start2.elapsed(), Duration::from_millis(250), Duration::from_millis(10));

        // Disable limit (unlimited)
        limiter.set_rate_limit(0).await;
        let start3 = tokio::time::Instant::now();
        limiter.acquire(1024 * 1024).await;
        assert_eq!(start3.elapsed(), Duration::ZERO);
    }

    #[tokio::test]
    async fn test_try_acquire() {
        tokio::time::pause();

        let limiter = RateLimiter::with_burst(10, 5120);

        // 5 KiB available immediately
        assert!(limiter.try_acquire(5120).await);

        // Bucket exhausted, immediate try_acquire fails
        assert!(!limiter.try_acquire(1024).await);

        // Advance time by 500ms (5 KiB replenished)
        tokio::time::advance(Duration::from_millis(500)).await;
        assert!(limiter.try_acquire(5120).await);
    }

    #[tokio::test]
    async fn test_bandwidth_limiter_dual_direction() {
        tokio::time::pause();

        let throttler = BandwidthLimiter::with_burst(10, 0, 20, 0);
        assert_eq!(throttler.upload_limit_kib().await, 10);
        assert_eq!(throttler.download_limit_kib().await, 20);

        let start = tokio::time::Instant::now();
        let (up_dur, dl_dur) = tokio::join!(
            async {
                throttler.acquire_upload(10240).await;
                start.elapsed()
            },
            async {
                throttler.acquire_download(10240).await;
                start.elapsed()
            }
        );

        // Concurrent execution:
        // Download: 10 KiB at 20 KiB/s = 500ms
        // Upload: 10 KiB at 10 KiB/s = 1000ms
        assert_approx_duration(dl_dur, Duration::from_millis(500), Duration::from_millis(15));
        assert_approx_duration(up_dur, Duration::from_secs(1), Duration::from_millis(15));
    }
}
