//! # tcp-brutal Congestion Control
//!
//! Adversarial pacing-based TCP congestion control .
//!
//! ## Algorithm Overview
//!
//! Unlike CUBIC or BBR which respond to packet loss by reducing the send rate,
//! tcp-brutal ignores standard TCP window back-offs. It:
//! 1. Tracks the ACK rate continuously as a percentage of sent packets.
//! 2. Applies inverse loss compensation: `rate = rate * 100 / ack_rate`.
//! 3. Clamps the pacing multiplier to prevent rate explosion under heavy loss.
//!
//! This is designed for censorship circumvention contexts where bandwidth
//! is intentionally constrained by adversarial middleboxes that throttle
//! connections by dropping packets — standard CCA capitulates to this; Brutal
//! does not.
//!
//! ## TCP Socket Configuration
//!
//! On Linux, Brutal is applied via `setsockopt(TCP_CONGESTION, "brutal")`.
//! On other platforms, the userspace pacing logic is emulated here.
//!
//! ## Source Projects
//! - `tcp-brutal` (Project 37) — Hysteria2/tcp-brutal congestion control kernel module
//! - Compendium §2.3.1: "tcp-brutal Congestion Control"

use std::time::{Duration, Instant};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Minimum pacing multiplier — prevents underflow even under 100% loss.
pub const BRUTAL_MIN_PACING_MULTIPLIER: f64 = 1.0;

/// Maximum pacing multiplier — prevents rate explosion.
pub const BRUTAL_MAX_PACING_MULTIPLIER: f64 = 8.0;

/// Minimum ACK rate below which we clamp to avoid division by near-zero.
pub const BRUTAL_MIN_ACK_RATE: f64 = 1.0;

/// Default target send rate in bytes per second.
pub const BRUTAL_DEFAULT_RATE_BPS: u64 = 50_000_000; // 50 MB/s

/// Window size for ACK rate tracking (number of RTT samples).
pub const BRUTAL_ACK_WINDOW: usize = 16;

/// Default initial RTT estimate.
pub const BRUTAL_DEFAULT_RTT: Duration = Duration::from_millis(100);

// ── Pacing Window ─────────────────────────────────────────────────────────────

/// A sliding window tracking sent vs acknowledged packet counts.
///
/// Used to compute the ACK rate as a percentage:
/// `ack_rate = (acked_in_window / sent_in_window) * 100`
pub struct AckRateWindow {
    sent: u64,
    acked: u64,
    /// Circular buffer of (sent_count, acked_count) per window slot.
    slots: [(u64, u64); BRUTAL_ACK_WINDOW],
    cursor: usize,
    last_update: Instant,
    slot_interval: Duration,
}

impl AckRateWindow {
    /// Creates a new ACK rate window with a per-slot interval based on RTT.
    pub fn new(rtt: Duration) -> Self {
        let slot_interval = rtt / BRUTAL_ACK_WINDOW as u32;
        Self {
            sent: 0,
            acked: 0,
            slots: [(0, 0); BRUTAL_ACK_WINDOW],
            cursor: 0,
            last_update: Instant::now(),
            slot_interval: slot_interval.max(Duration::from_millis(5)),
        }
    }

    /// Records a packet being sent.
    pub fn record_sent(&mut self, n: u64) {
        self.maybe_rotate();
        self.sent += n;
        self.slots[self.cursor].0 += n;
    }

    /// Records n packets being acknowledged.
    pub fn record_acked(&mut self, n: u64) {
        self.maybe_rotate();
        self.acked += n;
        self.slots[self.cursor].1 += n;
    }

    /// Rotates to the next slot if the slot interval has elapsed.
    fn maybe_rotate(&mut self) {
        if self.last_update.elapsed() >= self.slot_interval {
            // Move cursor and zero out old slot
            self.cursor = (self.cursor + 1) % BRUTAL_ACK_WINDOW;
            let (old_sent, old_acked) = self.slots[self.cursor];
            self.sent = self.sent.saturating_sub(old_sent);
            self.acked = self.acked.saturating_sub(old_acked);
            self.slots[self.cursor] = (0, 0);
            self.last_update = Instant::now();
        }
    }

    /// Returns the ACK rate as a percentage in [1.0, 100.0].
    pub fn ack_rate_percent(&self) -> f64 {
        if self.sent == 0 {
            return 100.0; // No packets sent yet — assume perfect delivery
        }
        let rate = (self.acked as f64 / self.sent as f64) * 100.0;
        rate.clamp(BRUTAL_MIN_ACK_RATE, 100.0)
    }
}

// ── Pacing Calculator ─────────────────────────────────────────────────────────

/// Computes the Brutal pacing multiplier from an ACK rate percentage.
///
/// Formula from tcp-brutal kernel module:
/// ```text
/// multiplier = 100 / ack_rate
/// ```
/// Clamped to `[MIN_PACING_MULTIPLIER, MAX_PACING_MULTIPLIER]`.
pub fn brutal_pacing_multiplier(ack_rate: f64) -> f64 {
    let rate = ack_rate.max(BRUTAL_MIN_ACK_RATE);
    let multiplier = 100.0 / rate;
    multiplier.clamp(BRUTAL_MIN_PACING_MULTIPLIER, BRUTAL_MAX_PACING_MULTIPLIER)
}

/// Computes the compensated send rate in bytes/sec.
///
/// Formula:
/// ```text
/// compensated_rate = target_rate_bps * (100 / ack_rate)
/// ```
/// Clamped to not exceed `target_rate * MAX_PACING_MULTIPLIER`.
pub fn brutal_compensated_rate(target_bps: u64, ack_rate: f64) -> u64 {
    let multiplier = brutal_pacing_multiplier(ack_rate);
    let compensated = (target_bps as f64 * multiplier) as u64;
    compensated.max(target_bps) // Never send less than the target
}

// ── TCP Socket Option Helper ──────────────────────────────────────────────────

/// The TCP congestion control algorithm name for `setsockopt(TCP_CONGESTION)`.
pub const TCP_CONGESTION_BRUTAL: &str = "brutal";

/// Attempts to set the TCP congestion control algorithm to "brutal" on a raw fd.
///
/// On Linux: calls `setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, "brutal\0", 7)`.
/// On other platforms: returns `Ok(())` (no-op; userspace Brutal emulation is used instead).
///
/// # Safety
/// The caller must ensure `fd` is a valid, open TCP socket file descriptor.
#[cfg(target_os = "linux")]
pub unsafe fn set_tcp_brutal(fd: std::os::unix::io::RawFd) -> Result<(), std::io::Error> {
    use std::io;
    // IPPROTO_TCP = 6, TCP_CONGESTION = 13
    const IPPROTO_TCP: libc::c_int = 6;
    const TCP_CONGESTION: libc::c_int = 13;
    let algo = b"brutal\0";
    let ret = libc::setsockopt(
        fd,
        IPPROTO_TCP,
        TCP_CONGESTION,
        algo.as_ptr() as *const libc::c_void,
        algo.len() as libc::socklen_t,
    );
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Non-Linux stub — Brutal TCP socket option is not available. Use userspace emulation.
#[cfg(not(target_os = "linux"))]
pub fn set_tcp_brutal_userspace_only() -> Result<(), BrutalError> {
    // No kernel-level Brutal on this platform; callers should use BrutalCongestionControl.
    Ok(())
}

// ── Error Types ───────────────────────────────────────────────────────────────

/// Errors produced by the Brutal CC implementation.
#[derive(Debug, thiserror::Error)]
pub enum BrutalError {
    #[error("Failed to set TCP_CONGESTION to 'brutal': {0}")]
    SetsockoptFailed(String),
    #[error("Target rate must be > 0 bps")]
    ZeroTargetRate,
}

// ── Congestion Controller ─────────────────────────────────────────────────────

/// Userspace tcp-brutal congestion controller.
///
/// Maintains a target send rate, tracks ACK rates via a sliding window,
/// and provides compensated rate recommendations for the send loop.
///
/// ## Usage Pattern
/// ```rust,no_run
/// let mut cc = BrutalCongestionControl::new(50_000_000); // 50 MB/s target
/// // In send loop:
/// cc.record_sent(1460); // one MSS sent
/// // ... network roundtrip ...
/// cc.record_acked(1460);
/// let send_rate = cc.effective_rate_bps(); // compensated rate to use
/// ```
pub struct BrutalCongestionControl {
    /// Target send rate in bytes per second.
    target_rate_bps: u64,
    /// Sliding window ACK rate tracker.
    ack_window: AckRateWindow,
    /// Current RTT estimate.
    rtt: Duration,
    /// Total bytes sent.
    total_sent: u64,
    /// Total bytes acknowledged.
    total_acked: u64,
    /// Controller creation time (for stats).
    started_at: Instant,
}

impl BrutalCongestionControl {
    /// Creates a new Brutal CC with the given target rate and default RTT.
    pub fn new(target_rate_bps: u64) -> Self {
        Self {
            target_rate_bps,
            ack_window: AckRateWindow::new(BRUTAL_DEFAULT_RTT),
            rtt: BRUTAL_DEFAULT_RTT,
            total_sent: 0,
            total_acked: 0,
            started_at: Instant::now(),
        }
    }

    /// Creates a new Brutal CC with an explicit initial RTT estimate.
    pub fn with_rtt(target_rate_bps: u64, rtt: Duration) -> Self {
        Self {
            target_rate_bps,
            ack_window: AckRateWindow::new(rtt),
            rtt,
            total_sent: 0,
            total_acked: 0,
            started_at: Instant::now(),
        }
    }

    /// Records bytes being sent.
    pub fn record_sent(&mut self, bytes: u64) {
        self.ack_window.record_sent(bytes);
        self.total_sent += bytes;
    }

    /// Records bytes being acknowledged.
    pub fn record_acked(&mut self, bytes: u64) {
        self.ack_window.record_acked(bytes);
        self.total_acked += bytes;
    }

    /// Updates the RTT estimate and re-initializes the window.
    pub fn update_rtt(&mut self, new_rtt: Duration) {
        self.rtt = new_rtt;
        // Re-initialize the window with the new RTT
        self.ack_window = AckRateWindow::new(new_rtt);
    }

    /// Returns the current ACK rate as a percentage [1.0, 100.0].
    pub fn ack_rate_percent(&self) -> f64 {
        self.ack_window.ack_rate_percent()
    }

    /// Returns the current pacing multiplier.
    pub fn pacing_multiplier(&self) -> f64 {
        brutal_pacing_multiplier(self.ack_rate_percent())
    }

    /// Returns the effective (compensated) send rate in bytes per second.
    ///
    /// This is the rate the sender SHOULD be using to achieve the target
    /// throughput despite packet loss.
    pub fn effective_rate_bps(&self) -> u64 {
        brutal_compensated_rate(self.target_rate_bps, self.ack_rate_percent())
    }

    /// Returns the nanosecond delay between MSS-sized sends at the effective rate.
    ///
    /// Useful for pacing the send loop:
    /// ```text
    /// sleep(pacing_delay_ns(1460)) between each write of 1460 bytes
    /// ```
    pub fn pacing_delay_ns(&self, segment_bytes: u64) -> u64 {
        let rate = self.effective_rate_bps();
        if rate == 0 {
            return 1_000_000_000; // 1 second safety fallback
        }
        // nanos_per_byte = 1_000_000_000 / rate
        // delay = nanos_per_byte * segment_bytes
        (segment_bytes * 1_000_000_000) / rate
    }

    /// Returns a `Duration` pacing delay between MSS-sized sends.
    pub fn pacing_delay(&self, segment_bytes: u64) -> Duration {
        Duration::from_nanos(self.pacing_delay_ns(segment_bytes))
    }

    /// Returns CC statistics as a human-readable string.
    pub fn stats(&self) -> String {
        format!(
            "BrutalCC {{ target={:.1}MB/s, ack_rate={:.1}%, multiplier={:.2}x, effective={:.1}MB/s, sent={:.1}MB, acked={:.1}MB, uptime={:.1}s }}",
            self.target_rate_bps as f64 / 1e6,
            self.ack_rate_percent(),
            self.pacing_multiplier(),
            self.effective_rate_bps() as f64 / 1e6,
            self.total_sent as f64 / 1e6,
            self.total_acked as f64 / 1e6,
            self.started_at.elapsed().as_secs_f64(),
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_brutal_pacing_multiplier_no_loss() {
        // 100% ACK rate → multiplier should be 1.0 (no compensation needed)
        let m = brutal_pacing_multiplier(100.0);
        assert!((m - 1.0).abs() < 1e-9, "expected multiplier=1.0, got {m}");
    }

    #[test]
    fn test_brutal_pacing_multiplier_50pct_loss() {
        // 50% ACK rate → multiplier should be 2.0
        let m = brutal_pacing_multiplier(50.0);
        assert!((m - 2.0).abs() < 1e-9, "expected multiplier=2.0, got {m}");
    }

    #[test]
    fn test_brutal_pacing_multiplier_clamped_high() {
        // Near-zero ACK rate should clamp to MAX_PACING_MULTIPLIER
        let m = brutal_pacing_multiplier(0.0001);
        assert_eq!(m, BRUTAL_MAX_PACING_MULTIPLIER);
    }

    #[test]
    fn test_brutal_pacing_multiplier_clamped_low() {
        // 200% ACK rate (impossible but test floor)
        let m = brutal_pacing_multiplier(200.0);
        assert_eq!(m, BRUTAL_MIN_PACING_MULTIPLIER);
    }

    #[test]
    fn test_brutal_compensated_rate_no_loss() {
        let target = 50_000_000u64; // 50 MB/s
        let compensated = brutal_compensated_rate(target, 100.0);
        assert_eq!(compensated, target, "no loss: compensated==target");
    }

    #[test]
    fn test_brutal_compensated_rate_50pct_loss() {
        let target = 10_000_000u64; // 10 MB/s
        let compensated = brutal_compensated_rate(target, 50.0);
        assert_eq!(compensated, 20_000_000, "50% loss: compensated=2x target");
    }

    #[test]
    fn test_brutal_compensated_rate_clamped() {
        let target = 10_000_000u64;
        // 1% ACK rate → would give 100x, but clamped to MAX_PACING_MULTIPLIER=8x
        let compensated = brutal_compensated_rate(target, 1.0);
        let max = (target as f64 * BRUTAL_MAX_PACING_MULTIPLIER) as u64;
        assert_eq!(compensated, max, "should be clamped at 8x");
    }

    #[test]
    fn test_ack_window_no_loss() {
        let mut w = AckRateWindow::new(Duration::from_millis(100));
        w.record_sent(1000);
        w.record_acked(1000);
        let rate = w.ack_rate_percent();
        assert!(
            (rate - 100.0).abs() < 0.1,
            "expected ~100% ACK rate, got {rate}"
        );
    }

    #[test]
    fn test_ack_window_50pct_loss() {
        let mut w = AckRateWindow::new(Duration::from_millis(100));
        w.record_sent(1000);
        w.record_acked(500);
        let rate = w.ack_rate_percent();
        assert!(
            (rate - 50.0).abs() < 0.1,
            "expected ~50% ACK rate, got {rate}"
        );
    }

    #[test]
    fn test_ack_window_zero_sent() {
        let w = AckRateWindow::new(Duration::from_millis(100));
        // No packets sent → assume perfect delivery
        assert_eq!(w.ack_rate_percent(), 100.0);
    }

    #[test]
    fn test_brutal_cc_creation() {
        let cc = BrutalCongestionControl::new(50_000_000);
        assert_eq!(cc.target_rate_bps, 50_000_000);
        assert_eq!(cc.ack_rate_percent(), 100.0); // No traffic yet
        assert_eq!(cc.pacing_multiplier(), 1.0);
    }

    #[test]
    fn test_brutal_cc_effective_rate_no_loss() {
        let mut cc = BrutalCongestionControl::new(50_000_000);
        cc.record_sent(10_000);
        cc.record_acked(10_000);
        let rate = cc.effective_rate_bps();
        assert_eq!(rate, 50_000_000, "no loss: effective==target");
    }

    #[test]
    fn test_brutal_cc_effective_rate_with_loss() {
        let mut cc = BrutalCongestionControl::new(10_000_000);
        cc.record_sent(1000);
        cc.record_acked(500); // 50% loss
        let rate = cc.effective_rate_bps();
        // Expected: 10 MB/s * (100/50) = 20 MB/s
        assert_eq!(rate, 20_000_000, "50% loss: effective=2x target");
    }

    #[test]
    fn test_brutal_cc_pacing_delay_no_loss() {
        let cc = BrutalCongestionControl::new(10_000); // 10 KB/s target
                                                       // At 10KB/s, sending 1 byte should take 100,000 ns = 0.1ms
        let delay = cc.pacing_delay_ns(1);
        assert_eq!(delay, 100_000, "1 byte at 10KB/s = 100µs");
    }

    #[test]
    fn test_brutal_cc_pacing_delay_mss() {
        let cc = BrutalCongestionControl::new(1_000_000); // 1 MB/s
                                                          // 1460 bytes at 1MB/s = 1.46ms
        let delay_ns = cc.pacing_delay_ns(1460);
        assert_eq!(
            delay_ns, 1_460_000,
            "1460 bytes at 1MB/s = 1460µs = 1,460,000ns"
        );
    }

    #[test]
    fn test_brutal_cc_stats_non_empty() {
        let mut cc = BrutalCongestionControl::new(50_000_000);
        cc.record_sent(1_000_000);
        cc.record_acked(1_000_000);
        let stats = cc.stats();
        assert!(stats.contains("BrutalCC"), "stats should contain BrutalCC");
        assert!(
            stats.contains("50.0MB/s"),
            "stats should contain target rate"
        );
    }

    #[test]
    fn test_brutal_cc_rtt_update() {
        let mut cc = BrutalCongestionControl::new(10_000_000);
        cc.update_rtt(Duration::from_millis(200));
        assert_eq!(cc.rtt, Duration::from_millis(200));
    }
}
