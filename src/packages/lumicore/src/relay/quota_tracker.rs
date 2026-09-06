//! Apps Script Account Quota Tracker
//!
//! Manages rolling 24-hour quota budgets across multiple fronting / relay script deployments.
//! Tracks byte transfer, request volume, error penalties, and exhaustion states.

use std::collections::HashMap;

const DEFAULT_WINDOW_SECONDS: u64 = 86_400; // 24 hours
const MAX_REQUESTS_PER_WINDOW: u64 = 20_000; // Apps Script free-tier daily ceiling

/// State tracking for an individual fronting script account deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountBucket {
    /// Masked script ID for diagnostics / logging (first 4 + "..." + last 4).
    pub masked_id: String,
    /// Requests consumed in the active sliding window.
    pub requests_used: u64,
    /// Failed requests in the active window.
    pub failed_requests: u64,
    /// Bytes sent upstream.
    pub bytes_up: u64,
    /// Bytes received downstream.
    pub bytes_down: u64,
    /// Total bytes transferred.
    pub bytes_total: u64,
    /// Unix timestamp of the last recorded interaction.
    pub last_request_at: Option<u64>,
    /// Unix timestamp when the 24-hour quota window resets.
    pub next_reset_at: Option<u64>,
    /// Whether the account is currently marked exhausted.
    pub exhausted: bool,
    /// Whether the account is temporarily quarantined due to repeat errors.
    pub quarantined: bool,
}

impl AccountBucket {
    pub fn new(script_id: &str) -> Self {
        Self {
            masked_id: mask_script_id(script_id),
            requests_used: 0,
            failed_requests: 0,
            bytes_up: 0,
            bytes_down: 0,
            bytes_total: 0,
            last_request_at: None,
            next_reset_at: None,
            exhausted: false,
            quarantined: false,
        }
    }
}

pub fn mask_script_id(id: &str) -> String {
    if id.len() <= 8 {
        return id.to_string();
    }
    format!("{}...{}", &id[..4], &id[id.len() - 4..])
}

/// Multi-account quota coordinator.
#[derive(Debug, Clone, Default)]
pub struct QuotaTracker {
    buckets: HashMap<String, AccountBucket>,
    window_duration_secs: u64,
    request_limit: u64,
}

impl QuotaTracker {
    pub fn new() -> Self {
        Self {
            buckets: HashMap::new(),
            window_duration_secs: DEFAULT_WINDOW_SECONDS,
            request_limit: MAX_REQUESTS_PER_WINDOW,
        }
    }

    pub fn with_limits(window_secs: u64, request_limit: u64) -> Self {
        Self {
            buckets: HashMap::new(),
            window_duration_secs: window_secs,
            request_limit,
        }
    }

    /// Registers a script account if not already tracked.
    pub fn register(&mut self, script_id: impl Into<String>) {
        let id = script_id.into();
        self.buckets.entry(id.clone()).or_insert_with(|| AccountBucket::new(&id));
    }

    /// Evaluates if the quota window for an account has expired and resets counters.
    pub fn check_and_reset_window(&mut self, script_id: &str, now_unix: u64) {
        if let Some(bucket) = self.buckets.get_mut(script_id) {
            if let Some(reset_at) = bucket.next_reset_at {
                if now_unix >= reset_at {
                    bucket.requests_used = 0;
                    bucket.failed_requests = 0;
                    bucket.bytes_up = 0;
                    bucket.bytes_down = 0;
                    bucket.bytes_total = 0;
                    bucket.next_reset_at = None;
                    bucket.exhausted = false;
                    bucket.quarantined = false;
                }
            }
        }
    }

    /// Records an executed request outcome.
    pub fn record_outcome(
        &mut self,
        script_id: &str,
        now_unix: u64,
        up_bytes: u64,
        down_bytes: u64,
        success: bool,
    ) {
        self.check_and_reset_window(script_id, now_unix);

        let window_duration = self.window_duration_secs;
        let limit = self.request_limit;

        let bucket = self.buckets.entry(script_id.to_string()).or_insert_with(|| AccountBucket::new(script_id));

        if bucket.next_reset_at.is_none() {
            bucket.next_reset_at = Some(now_unix + window_duration);
        }

        bucket.last_request_at = Some(now_unix);
        bucket.requests_used += 1;
        bucket.bytes_up += up_bytes;
        bucket.bytes_down += down_bytes;
        bucket.bytes_total += up_bytes + down_bytes;

        if !success {
            bucket.failed_requests += 1;
            if bucket.failed_requests >= 5 {
                bucket.quarantined = true;
            }
        }

        if bucket.requests_used >= limit {
            bucket.exhausted = true;
        }
    }

    /// Marks an account as manually exhausted.
    pub fn mark_exhausted(&mut self, script_id: &str, now_unix: u64) {
        if let Some(bucket) = self.buckets.get_mut(script_id) {
            bucket.exhausted = true;
            if bucket.next_reset_at.is_none() {
                bucket.next_reset_at = Some(now_unix + self.window_duration_secs);
            }
        }
    }

    /// Selects the optimal available account (un-exhausted, un-quarantined, lowest requests used).
    pub fn select_best_account(&mut self, now_unix: u64) -> Option<String> {
        let keys: Vec<String> = self.buckets.keys().cloned().collect();
        for k in &keys {
            self.check_and_reset_window(k, now_unix);
        }

        self.buckets
            .iter()
            .filter(|(_, b)| !b.exhausted && !b.quarantined)
            .min_by_key(|(_, b)| b.requests_used)
            .map(|(k, _)| k.clone())
    }

    /// Returns diagnostic summary for a specific script.
    pub fn get_bucket(&self, script_id: &str) -> Option<&AccountBucket> {
        self.buckets.get(script_id)
    }

    /// Total count of registered accounts.
    pub fn account_count(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_masking() {
        assert_eq!(mask_script_id("short"), "short");
        assert_eq!(mask_script_id("AKfycbz1234567890abcdef"), "AKfy...cdef");
    }

    #[test]
    fn test_quota_rollover() {
        let mut tracker = QuotaTracker::with_limits(100, 3);
        let id = "script-alpha";
        tracker.register(id);

        let t0 = 1_000;
        tracker.record_outcome(id, t0, 100, 200, true);
        tracker.record_outcome(id, t0 + 1, 100, 200, true);
        tracker.record_outcome(id, t0 + 2, 100, 200, true);

        let b = tracker.get_bucket(id).unwrap();
        assert_eq!(b.requests_used, 3);
        assert!(b.exhausted);
        assert_eq!(tracker.select_best_account(t0 + 10), None);

        // After window expires:
        let t_expired = t0 + 101;
        assert_eq!(tracker.select_best_account(t_expired), Some(id.to_string()));
        let b2 = tracker.get_bucket(id).unwrap();
        assert_eq!(b2.requests_used, 0);
        assert!(!b2.exhausted);
    }

    #[test]
    fn test_multi_account_load_balancing() {
        let mut tracker = QuotaTracker::with_limits(100, 10);
        tracker.register("acc1");
        tracker.register("acc2");

        let best1 = tracker.select_best_account(1000).unwrap();
        tracker.record_outcome(&best1, 1000, 50, 50, true);

        let best2 = tracker.select_best_account(1001).unwrap();
        assert_ne!(best1, best2); // Alternate to the least-used account
    }
}
