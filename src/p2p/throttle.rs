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
                if state.rate_bytes_per_sec > 0.0 {
                    let elapsed = (now - state.last_replenish).as_secs_f64();
                    state.tokens = (state.tokens + elapsed * state.rate_bytes_per_sec).min(state.burst_capacity);
                }
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
        state.tokens = (state.tokens + elapsed * state.rate_bytes_per_sec).min(state.burst_capacity);
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
                state.tokens = (state.tokens + elapsed * state.rate_bytes_per_sec).min(state.burst_capacity);
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

    #[tokio::test]
    async fn test_high_concurrency_mass_tasks() {
        tokio::time::pause();

        // 50 KiB/s rate limit (51,200 bytes/sec), 0 burst
        let limiter = Arc::new(RateLimiter::with_burst(50, 0));
        let start = tokio::time::Instant::now();

        // 50 concurrent tasks each acquiring 1024 bytes (1 KiB)
        // Total bytes = 50 * 1024 = 51200 bytes
        // Expected total duration = exactly 1 second
        let mut handles = Vec::new();
        for _ in 0..50 {
            let l = limiter.clone();
            handles.push(tokio::spawn(async move {
                l.acquire(1024).await;
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        let elapsed = start.elapsed();
        assert_approx_duration(elapsed, Duration::from_secs(1), Duration::from_millis(30));
    }

    #[tokio::test]
    async fn test_high_concurrency_varying_chunk_sizes() {
        tokio::time::pause();

        // 100 KiB/s rate limit (102,400 bytes/sec), 0 burst
        let limiter = Arc::new(RateLimiter::with_burst(100, 0));
        let start = tokio::time::Instant::now();

        // 40 tasks with varying chunk sizes: 10 of 1024, 10 of 2048, 10 of 3072, 10 of 4096
        // Total bytes = 10 * (1024 + 2048 + 3072 + 4096) = 10 * 10240 = 102,400 bytes (100 KiB)
        // Expected total duration = 1.0 second
        let mut handles = Vec::new();
        let chunk_sizes = [1024, 2048, 3072, 4096];
        for i in 0..40 {
            let l = limiter.clone();
            let size = chunk_sizes[i % 4];
            handles.push(tokio::spawn(async move {
                l.acquire(size).await;
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        let elapsed = start.elapsed();
        assert_approx_duration(elapsed, Duration::from_secs(1), Duration::from_millis(30));
    }

    #[tokio::test]
    async fn test_burst_accumulation_cap() {
        tokio::time::pause();

        // 20 KiB/s rate limit, 10 KiB burst capacity (10,240 bytes)
        let limiter = RateLimiter::with_burst(20, 10240);

        // Bucket starts full with 10 KiB burst
        assert_eq!(limiter.available_tokens().await, 10240);

        // Advance time by 60 seconds of idle time
        tokio::time::advance(Duration::from_secs(60)).await;

        // Available tokens must NEVER exceed configured burst capacity
        assert_eq!(limiter.available_tokens().await, 10240);

        // Acquire the entire 10 KiB burst instantly
        let start = tokio::time::Instant::now();
        limiter.acquire(10240).await;
        assert_eq!(start.elapsed(), Duration::ZERO);

        // Bucket is now exhausted; immediate try_acquire fails
        assert!(!limiter.try_acquire(1).await);
        assert_eq!(limiter.available_tokens().await, 0);

        // Another 10 KiB must now sleep for 500ms (10 KiB / 20 KiB/s = 0.5s)
        let start2 = tokio::time::Instant::now();
        limiter.acquire(10240).await;
        assert_approx_duration(start2.elapsed(), Duration::from_millis(500), Duration::from_millis(15));
    }

    #[tokio::test]
    async fn test_burst_dynamic_replenishment_over_time() {
        tokio::time::pause();

        // 10 KiB/s, 10 KiB burst
        let limiter = RateLimiter::with_burst(10, 10240);

        // Drain entire burst
        assert!(limiter.try_acquire(10240).await);
        assert_eq!(limiter.available_tokens().await, 0);

        // Step 1: Advance by 250ms -> 2.5 KiB (2560 bytes) replenished
        tokio::time::advance(Duration::from_millis(250)).await;
        assert_eq!(limiter.available_tokens().await, 2560);
        assert!(limiter.try_acquire(2560).await);
        assert_eq!(limiter.available_tokens().await, 0);

        // Step 2: Advance by 500ms -> 5 KiB (5120 bytes) replenished
        tokio::time::advance(Duration::from_millis(500)).await;
        assert_eq!(limiter.available_tokens().await, 5120);

        // Consume 2048 bytes; 3072 bytes should remain
        assert!(limiter.try_acquire(2048).await);
        assert_eq!(limiter.available_tokens().await, 3072);

        // Step 3: Advance 2 seconds -> should top off to full burst (10240)
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(limiter.available_tokens().await, 10240);
    }

    #[tokio::test]
    async fn test_dynamic_reconfiguration_during_active_debt() {
        tokio::time::pause();

        // 10 KiB/s, 0 burst
        let limiter = Arc::new(RateLimiter::with_burst(10, 0));

        // Task 1 acquires 10 KiB -> takes 1.0s
        let l1 = limiter.clone();
        let h1 = tokio::spawn(async move {
            let start = tokio::time::Instant::now();
            l1.acquire(10240).await;
            start.elapsed()
        });

        // Let task 1 start and establish its reservation
        tokio::task::yield_now().await;

        // While task 1 is in-flight, double bandwidth to 20 KiB/s
        limiter.set_rate_limit(20).await;

        // Task 2 now acquires 10 KiB at 20 KiB/s (adds 0.5s to the adjusted debt)
        let l2 = limiter.clone();
        let h2 = tokio::spawn(async move {
            let start = tokio::time::Instant::now();
            l2.acquire(10240).await;
            start.elapsed()
        });

        let t1 = h1.await.unwrap();
        let t2 = h2.await.unwrap();

        // Task 1 was scheduled for 10 KiB / 10 KiB/s = 1.0s
        assert_approx_duration(t1, Duration::from_secs(1), Duration::from_millis(20));

        // When set_rate_limit(20) was called at t=0, Task 1's debt was 10 KiB,
        // which scaled to 10 KiB / 20 KiB/s = 0.5s.
        // Task 2 added 10 KiB / 20 KiB/s = 0.5s.
        // Thus Task 2 wakes up at 0.5s + 0.5s = 1.0s!
        assert_approx_duration(t2, Duration::from_secs(1), Duration::from_millis(20));
    }

    #[tokio::test]
    async fn test_dynamic_reconfiguration_slowdown_during_active_debt() {
        tokio::time::pause();

        // 20 KiB/s, 0 burst
        let limiter = Arc::new(RateLimiter::with_burst(20, 0));

        // Task 1 acquires 20 KiB at 20 KiB/s (initial debt 1.0s)
        let l1 = limiter.clone();
        let h1 = tokio::spawn(async move {
            let start = tokio::time::Instant::now();
            l1.acquire(20480).await;
            start.elapsed()
        });

        tokio::task::yield_now().await;

        // Slow down to 10 KiB/s at runtime
        limiter.set_rate_limit(10).await;

        // Task 2 acquires 10 KiB
        let l2 = limiter.clone();
        let h2 = tokio::spawn(async move {
            let start = tokio::time::Instant::now();
            l2.acquire(10240).await;
            start.elapsed()
        });

        let t1 = h1.await.unwrap();
        let t2 = h2.await.unwrap();

        // Task 1 completes after its initial 1s sleep
        assert_approx_duration(t1, Duration::from_secs(1), Duration::from_millis(20));

        // At t=0, 20 KiB debt scaled to 10 KiB/s = 2.0s wait.
        // Task 2 adds 10 KiB / 10 KiB/s = 1.0s.
        // Total wait for Task 2 = 3.0s!
        assert_approx_duration(t2, Duration::from_secs(3), Duration::from_millis(25));
    }

    #[tokio::test]
    async fn test_dynamic_reconfiguration_to_unlimited_and_back() {
        tokio::time::pause();

        let limiter = RateLimiter::with_burst(10, 0);

        // Initial throttled acquire
        let start = tokio::time::Instant::now();
        limiter.acquire(10240).await;
        assert_approx_duration(start.elapsed(), Duration::from_secs(1), Duration::from_millis(15));

        // Switch to unlimited (0 KiB/s)
        limiter.set_rate_limit(0).await;
        assert_eq!(limiter.limit_kib().await, 0);
        assert_eq!(limiter.available_tokens().await, usize::MAX);

        // Zero delay on 50 MB
        let start2 = tokio::time::Instant::now();
        limiter.acquire(50 * 1024 * 1024).await;
        assert_eq!(start2.elapsed(), Duration::ZERO);

        // Switch back to 50 KiB/s with 0 burst
        limiter.set_rate_limit(50).await;
        assert_eq!(limiter.limit_kib().await, 50);

        // Acquiring 25 KiB at 50 KiB/s takes 500ms
        let start3 = tokio::time::Instant::now();
        limiter.acquire(25600).await;
        assert_approx_duration(start3.elapsed(), Duration::from_millis(500), Duration::from_millis(15));
    }

    #[tokio::test]
    async fn test_high_concurrency_bandwidth_limiter_bi_directional() {
        tokio::time::pause();

        // Upload: 25 KiB/s (0 burst), Download: 50 KiB/s (0 burst)
        let limiter = Arc::new(BandwidthLimiter::with_burst(25, 0, 50, 0));
        let start = tokio::time::Instant::now();

        // 25 concurrent upload tasks of 1024 bytes -> 25 KiB total -> 1.0s
        let mut upload_handles = Vec::new();
        for _ in 0..25 {
            let l = limiter.clone();
            upload_handles.push(tokio::spawn(async move {
                l.acquire_upload(1024).await;
            }));
        }

        // 25 concurrent download tasks of 2048 bytes -> 50 KiB total -> 1.0s
        let mut download_handles = Vec::new();
        for _ in 0..25 {
            let l = limiter.clone();
            download_handles.push(tokio::spawn(async move {
                l.acquire_download(2048).await;
            }));
        }

        for h in upload_handles {
            h.await.unwrap();
        }
        for h in download_handles {
            h.await.unwrap();
        }

        // Both streams ran concurrently, each completing their respective quotas in ~1s
        let elapsed = start.elapsed();
        assert_approx_duration(elapsed, Duration::from_secs(1), Duration::from_millis(30));
    }

    #[tokio::test]
    async fn test_bandwidth_limiter_runtime_reconfiguration() {
        tokio::time::pause();

        let limiter = BandwidthLimiter::with_burst(10, 0, 20, 0);
        assert_eq!(limiter.upload_limit_kib().await, 10);
        assert_eq!(limiter.download_limit_kib().await, 20);

        // Reconfigure upload only
        limiter.set_upload_limit(50).await;
        assert_eq!(limiter.upload_limit_kib().await, 50);
        assert_eq!(limiter.download_limit_kib().await, 20); // download unchanged

        // Reconfigure download only
        limiter.set_download_limit(100).await;
        assert_eq!(limiter.upload_limit_kib().await, 50); // upload unchanged
        assert_eq!(limiter.download_limit_kib().await, 100);

        // Verify transfer rates reflect new independent limits concurrently
        let start = tokio::time::Instant::now();
        let (up_dur, dl_dur) = tokio::join!(
            async {
                limiter.acquire_upload(25600).await; // 25 KiB at 50 KiB/s = 500ms
                start.elapsed()
            },
            async {
                limiter.acquire_download(51200).await; // 50 KiB at 100 KiB/s = 500ms
                start.elapsed()
            }
        );
        assert_approx_duration(up_dur, Duration::from_millis(500), Duration::from_millis(15));
        assert_approx_duration(dl_dur, Duration::from_millis(500), Duration::from_millis(15));
    }
}
