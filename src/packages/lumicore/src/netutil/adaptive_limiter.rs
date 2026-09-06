
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

/// A smart concurrency limiter that backs off when remote servers reject requests,
/// and ramps up when things are going well.
pub struct AdaptiveLimiter {
    max: AtomicUsize,
    current: AtomicUsize,
    active: AtomicUsize,
    success_streak: AtomicUsize,
    blocked_until: Mutex<Option<Instant>>,
    notify: Notify,
}

impl AdaptiveLimiter {
    pub fn new(max: usize) -> Self {
        Self {
            max: AtomicUsize::new(max),
            current: AtomicUsize::new(max),
            active: AtomicUsize::new(0),
            success_streak: AtomicUsize::new(0),
            blocked_until: Mutex::new(None),
            notify: Notify::new(),
        }
    }

    pub fn configure(&self, max_concurrency: usize) {
        let max = max_concurrency.clamp(1, 100);
        self.max.store(max, Ordering::Release);
        self.current.store(max, Ordering::Release);
        self.success_streak.store(0, Ordering::Release);
        if let Ok(mut guard) = self.blocked_until.lock() {
            *guard = None;
        }
        self.notify.notify_waiters();
    }

    pub async fn acquire(&'static self) -> AdaptivePermit {
        loop {
            let blocked_until = self.blocked_until.lock().ok().and_then(|guard| *guard);
            if let Some(until) = blocked_until {
                let now = Instant::now();
                if until > now {
                    tokio::time::sleep_until(tokio::time::Instant::from_std(until)).await;
                    continue;
                }
            }

            let limit = self.current.load(Ordering::Acquire).max(1);
            let active = self.active.load(Ordering::Acquire);
            if active < limit
                && self
                    .active
                    .compare_exchange(active, active + 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                return AdaptivePermit { limiter: self };
            }

            self.notify.notified().await;
        }
    }

    pub fn record_success(&self) {
        let limit = self.current.load(Ordering::Acquire);
        let max = self.max.load(Ordering::Acquire);
        if limit >= max {
            return;
        }

        let streak = self.success_streak.fetch_add(1, Ordering::AcqRel) + 1;
        if streak >= limit.max(1) {
            self.success_streak.store(0, Ordering::Release);
            let _ = self.current.compare_exchange(
                limit,
                (limit + 1).min(max),
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            self.notify.notify_waiters();
        }
    }

    pub fn record_rate_limit(&self, retry_after_ms: Option<u64>) {
        let current = self.current.load(Ordering::Acquire).max(1);
        let next = (current / 2).max(1);
        self.current.store(next, Ordering::Release);
        self.success_streak.store(0, Ordering::Release);

        if let Some(retry_after_ms) = retry_after_ms {
            let capped_ms = retry_after_ms.clamp(500, 60_000);
            let next_until = Instant::now() + Duration::from_millis(capped_ms);
            if let Ok(mut guard) = self.blocked_until.lock() {
                if guard.is_none_or(|until| next_until > until) {
                    *guard = Some(next_until);
                }
            }
        }

        self.notify.notify_waiters();
    }

    pub fn record_server_error(&self) {
        let current = self.current.load(Ordering::Acquire).max(1);
        self.current
            .store(current.saturating_sub(1).max(1), Ordering::Release);
        self.success_streak.store(0, Ordering::Release);
        self.notify.notify_waiters();
    }

    pub fn current_limit(&self) -> usize {
        self.current.load(Ordering::Acquire)
    }

    pub fn active_permits(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
}

pub struct AdaptivePermit {
    limiter: &'static AdaptiveLimiter,
}

impl Drop for AdaptivePermit {
    fn drop(&mut self) {
        self.limiter.active.fetch_sub(1, Ordering::Release);
        self.limiter.notify.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LIMITER: AdaptiveLimiter = AdaptiveLimiter {
        max: AtomicUsize::new(3),
        current: AtomicUsize::new(3),
        active: AtomicUsize::new(0),
        success_streak: AtomicUsize::new(0),
        blocked_until: Mutex::new(None),
        notify: Notify::const_new(),
    };

    #[tokio::test]
    async fn test_adaptive_limiter_streaks() {
        TEST_LIMITER.configure(3);
        assert_eq!(TEST_LIMITER.current_limit(), 3);

        {
            let _p1 = TEST_LIMITER.acquire().await;
            let _p2 = TEST_LIMITER.acquire().await;
            let _p3 = TEST_LIMITER.acquire().await;
            assert_eq!(TEST_LIMITER.active_permits(), 3);
        }

        // Record a rate limit: limit should halve to 1
        TEST_LIMITER.record_rate_limit(None);
        assert_eq!(TEST_LIMITER.current_limit(), 1);

        // Record success: should increase back to 2, then to 3
        TEST_LIMITER.record_success();
        assert_eq!(TEST_LIMITER.current_limit(), 2);
    }
}
