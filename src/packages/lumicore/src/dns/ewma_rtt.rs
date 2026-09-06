//! # EWMA-RTT Tracker (Rust)
//!
//! Exponentially Weighted Moving Average (EWMA) round-trip time estimator for
//! DNS upstreams. Ports the RFC 6298 TCP retransmit timer to DNS, enabling
//! latency-sensitive load balancing, racing, and anomaly detection.
//!
//! The EWMA in this module uses the same update rules as the Unix kernel TCP
//! stack (RFC 6298 §2.2):
//!   SRTT <- (1 - alpha) * SRTT + alpha * R'
//!   RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R'|
//!   RTO <- SRTT + max(G, 4 * RTTVAR)
//!
//! where alpha = 0.125 and beta = 0.25 by default (RFC 6298 values).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// EWMA RTT estimator for a single upstream.
#[derive(Debug, Clone)]
pub struct EWMARtt {
    /// Smoothing factor (alpha). RFC 6298 default is 0.125.
    alpha: f64,
    /// Smoothed round-trip time.
    srtt: Duration,
    /// RTT variance estimate.
    rttvar: Duration,
    /// Whether at least one sample has been observed.
    initialized: bool,
    /// Most recent sample timestamp (for optional freshness checks).
    last_sample: Option<Instant>,
}

impl Default for EWMARtt {
    fn default() -> Self {
        Self::new(0.125)
    }
}

impl EWMARtt {
    /// Construct a tracker with the given smoothing factor alpha.
    /// Alpha must be in (0, 1]. Values outside this range fall back to 0.125.
    pub fn new(alpha: f64) -> Self {
        Self {
            alpha: if alpha > 0.0 && alpha <= 1.0 { alpha } else { 0.125 },
            srtt: Duration::ZERO,
            rttvar: Duration::ZERO,
            initialized: false,
            last_sample: None,
        }
    }

    /// Observe a new RTT sample. The first sample seeds both SRTT and RTTVAR;
    /// subsequent samples are smoothed using the RFC 6298 update rules.
    pub fn observe(&mut self, rtt: Duration) {
        if rtt.is_zero() {
            return; // ignore zero samples (would corrupt variance)
        }
        self.last_sample = Some(Instant::now());
        if !self.initialized {
            self.srtt = rtt;
            self.rttvar = rtt / 2;
            self.initialized = true;
            return;
        }
        // err = |SRTT - R'|
        let err = if self.srtt > rtt {
            self.srtt - rtt
        } else {
            rtt - self.srtt
        };
        // RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R'|
        let beta = 0.25;
        let rttvar_sample = (1.0 - beta) * self.rttvar.as_secs_f64()
            + beta * err.as_secs_f64();
        self.rttvar = Duration::from_secs_f64(rttvar_sample);
        // SRTT <- (1 - alpha) * SRTT + alpha * R'
        let srtt_sample = (1.0 - self.alpha) * self.srtt.as_secs_f64()
            + self.alpha * rtt.as_secs_f64();
        self.srtt = Duration::from_secs_f64(srtt_sample);
    }

    /// Returns the current smoothed RTT estimate. Returns None if no sample
    /// has been observed yet.
    pub fn smoothed(&self) -> Option<Duration> {
        if self.initialized {
            Some(self.srtt)
        } else {
            None
        }
    }

    /// Returns the estimated retransmission timeout (RTO) per RFC 6298.
    /// Returns None if no sample has been observed.
    pub fn rto(&self) -> Option<Duration> {
        if !self.initialized {
            return None;
        }
        let g = Duration::from_millis(1); // clock granularity
        let variance = 4 * self.rttvar;
        let variance = if variance < g { g } else { variance };
        Some(self.srtt + variance)
    }

    /// Reports whether at least one sample has been observed.
    pub fn initialized(&self) -> bool {
        self.initialized
    }

    /// Resets the estimator to its initial state.
    pub fn reset(&mut self) {
        self.srtt = Duration::ZERO;
        self.rttvar = Duration::ZERO;
        self.initialized = false;
        self.last_sample = None;
    }

    /// Returns the elapsed time since the last sample, or None if no sample
    /// has been observed.
    pub fn since_last_sample(&self) -> Option<Duration> {
        self.last_sample.map(|t| t.elapsed())
    }
}

/// Thread-safe registry of per-upstream EWMA RTT trackers.
#[derive(Debug, Default, Clone)]
pub struct EWMARttRegistry {
    inner: Arc<RwLock<HashMap<String, EWMARtt>>>,
    alpha: f64,
}

impl EWMARttRegistry {
    /// Construct a new registry with the given smoothing factor.
    pub fn new(alpha: f64) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            alpha: if alpha > 0.0 && alpha <= 1.0 { alpha } else { 0.125 },
        }
    }

    /// Returns (or creates) the tracker for the given upstream ID.
    pub fn for_upstream(&self, id: &str) -> Arc<RwLock<EWMARtt>> {
        {
            let guard = self.inner.read().unwrap();
            if let Some(tracker) = guard.get(id) {
                return Arc::new(RwLock::new(tracker.clone()));
            }
        }
        let mut guard = self.inner.write().unwrap();
        // Re-check after acquiring write lock.
        if let Some(tracker) = guard.get(id) {
            return Arc::new(RwLock::new(tracker.clone()));
        }
        let tracker = EWMARtt::new(self.alpha);
        let arc = Arc::new(RwLock::new(tracker.clone()));
        guard.insert(id.to_string(), tracker);
        arc
    }

    /// Removes the tracker for the given upstream ID.
    pub fn forget(&self, id: &str) {
        self.inner.write().unwrap().remove(id);
    }

    /// Returns the IDs of currently tracked upstreams.
    pub fn tracked_ids(&self) -> Vec<String> {
        self.inner.read().unwrap().keys().cloned().collect()
    }

    /// Returns the count of tracked upstreams.
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    /// Reports whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_ewma_uninitialised() {
        let e = EWMARtt::new(0.125);
        assert!(!e.initialized());
        assert!(e.smoothed().is_none());
        assert!(e.rto().is_none());
    }

    #[test]
    fn test_first_sample_seeds() {
        let mut e = EWMARtt::new(0.125);
        e.observe(Duration::from_millis(100));
        assert!(e.initialized());
        assert_eq!(e.smoothed(), Some(Duration::from_millis(100)));
    }

    #[test]
    fn test_smoothing_alpha_half() {
        let mut e = EWMARtt::new(0.5);
        e.observe(Duration::from_millis(100));
        e.observe(Duration::from_millis(200));
        // SRTT = (1-0.5)*100 + 0.5*200 = 150
        assert_eq!(e.smoothed(), Some(Duration::from_millis(150)));
        e.observe(Duration::from_millis(200));
        // SRTT = (1-0.5)*150 + 0.5*200 = 175
        assert_eq!(e.smoothed(), Some(Duration::from_millis(175)));
    }

    #[test]
    fn test_rto_at_least_srtt() {
        let mut e = EWMARtt::new(0.125);
        e.observe(Duration::from_millis(50));
        let rto = e.rto().unwrap();
        assert!(rto >= e.smoothed().unwrap());
    }

    #[test]
    fn test_reset() {
        let mut e = EWMARtt::new(0.125);
        e.observe(Duration::from_millis(100));
        e.reset();
        assert!(!e.initialized());
        assert!(e.smoothed().is_none());
    }

    #[test]
    fn test_zero_sample_ignored() {
        let mut e = EWMARtt::new(0.125);
        e.observe(Duration::from_millis(50));
        e.observe(Duration::ZERO);
        assert_eq!(e.smoothed(), Some(Duration::from_millis(50)));
    }

    #[test]
    fn test_invalid_alpha_falls_back() {
        for bad in [-1.0, 0.0, 1.5, 999.0, f64::NAN] {
            let e = EWMARtt::new(bad);
            assert_eq!(e.alpha, 0.125);
        }
    }

    #[test]
    fn test_registry_per_upstream_isolation() {
        let reg = EWMARttRegistry::new(0.125);
        let a = reg.for_upstream("a");
        let b = reg.for_upstream("b");
        {
            let mut a_write = a.write().unwrap();
            a_write.observe(Duration::from_millis(10));
        }
        {
            let mut b_write = b.write().unwrap();
            b_write.observe(Duration::from_millis(1000));
        }
        assert_eq!(a.read().unwrap().smoothed(), Some(Duration::from_millis(10)));
        assert_eq!(b.read().unwrap().smoothed(), Some(Duration::from_millis(1000)));
    }

    #[test]
    fn test_registry_forget() {
        let reg = EWMARttRegistry::new(0.125);
        reg.for_upstream("x");
        assert_eq!(reg.len(), 1);
        reg.forget("x");
        assert!(reg.is_empty());
    }

    #[test]
    fn test_registry_tracked_ids() {
        let reg = EWMARttRegistry::new(0.125);
        reg.for_upstream("a");
        reg.for_upstream("b");
        reg.for_upstream("c");
        let ids = reg.tracked_ids();
        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&"a".to_string()));
    }

    #[test]
    fn test_since_last_sample() {
        let mut e = EWMARtt::new(0.125);
        assert!(e.since_last_sample().is_none());
        e.observe(Duration::from_millis(50));
        assert!(e.since_last_sample().is_some());
        // Elapsed should be non-negative.
        let elapsed = e.since_last_sample().unwrap();
        assert!(elapsed >= Duration::ZERO);
    }
}
