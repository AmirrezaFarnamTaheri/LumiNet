use std::collections::HashSet;
use std::time::Duration;

/// Exponential moving average smoothing weights: 0.4 historical, 0.6 incoming sample.
const SMOOTH_PREV_WEIGHT: f64 = 0.4;
const SMOOTH_SAMPLE_WEIGHT: f64 = 0.6;

/// Snapshot of traffic volume and current transfer speed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrafficSample {
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub download_bytes_per_sec: u64,
    pub upload_bytes_per_sec: u64,
    pub supported: bool,
}

/// Smoothed rate meter calculating exponential moving average of throughput.
#[derive(Debug, Clone)]
pub struct TrafficMeterSmoother {
    base_rx: u64,
    base_tx: u64,
    last_rx: u64,
    last_tx: u64,
    smoothed_down: f64,
    smoothed_up: f64,
    initialized: bool,
}

impl Default for TrafficMeterSmoother {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficMeterSmoother {
    pub fn new() -> Self {
        Self {
            base_rx: 0,
            base_tx: 0,
            last_rx: 0,
            last_tx: 0,
            smoothed_down: 0.0,
            smoothed_up: 0.0,
            initialized: false,
        }
    }

    pub fn start(&mut self, current_rx: u64, current_tx: u64) {
        self.base_rx = current_rx;
        self.base_tx = current_tx;
        self.last_rx = current_rx;
        self.last_tx = current_tx;
        self.smoothed_down = 0.0;
        self.smoothed_up = 0.0;
        self.initialized = true;
    }

    pub fn sample_now(&mut self, current_rx: u64, current_tx: u64, elapsed: Duration) -> TrafficSample {
        if !self.initialized {
            self.start(current_rx, current_tx);
            return TrafficSample {
                received_bytes: 0,
                sent_bytes: 0,
                download_bytes_per_sec: 0,
                upload_bytes_per_sec: 0,
                supported: true,
            };
        }

        let delta_rx = current_rx.saturating_sub(self.last_rx);
        let delta_tx = current_tx.saturating_sub(self.last_tx);

        let elapsed_nanos = elapsed.as_nanos() as u64;
        let per_second = |delta: u64| -> u64 {
            if elapsed_nanos == 0 {
                0
            } else {
                delta.saturating_mul(1_000_000_000) / elapsed_nanos
            }
        };

        let raw_down = per_second(delta_rx) as f64;
        let raw_up = per_second(delta_tx) as f64;

        self.smoothed_down = if self.smoothed_down <= 0.0 {
            raw_down
        } else {
            self.smoothed_down * SMOOTH_PREV_WEIGHT + raw_down * SMOOTH_SAMPLE_WEIGHT
        };

        self.smoothed_up = if self.smoothed_up <= 0.0 {
            raw_up
        } else {
            self.smoothed_up * SMOOTH_PREV_WEIGHT + raw_up * SMOOTH_SAMPLE_WEIGHT
        };

        self.last_rx = current_rx;
        self.last_tx = current_tx;

        TrafficSample {
            received_bytes: current_rx.saturating_sub(self.base_rx),
            sent_bytes: current_tx.saturating_sub(self.base_tx),
            download_bytes_per_sec: self.smoothed_down as u64,
            upload_bytes_per_sec: self.smoothed_up as u64,
            supported: true,
        }
    }

    pub fn stop(&mut self) {
        self.smoothed_down = 0.0;
        self.smoothed_up = 0.0;
    }
}

/// Formats a byte count into a human-readable string (B, KB, MB, GB, TB).
pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let units = ["KB", "MB", "GB", "TB"];
    let mut val = bytes as f64 / 1024.0;
    let mut idx = 0;
    while val >= 1024.0 && idx < units.len() - 1 {
        val /= 1024.0;
        idx += 1;
    }
    if val < 10.0 {
        format!("{:.1} {}", val, units[idx])
    } else {
        format!("{:.0} {}", val, units[idx])
    }
}

/// Formats a throughput rate into a human-readable string (e.g. "9.4 MB/s").
pub fn format_rate(bytes_per_sec: u64) -> String {
    format!("{}/s", format_bytes(bytes_per_sec))
}

/// Per-application routing policy mode for split tunneling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitTunnelMode {
    All,
    Only,
    Except,
}

/// Split tunnel policy configuration protecting against self-capture loops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitTunnelPolicy {
    pub mode: SplitTunnelMode,
    pub targets: HashSet<String>,
}

impl Default for SplitTunnelPolicy {
    fn default() -> Self {
        Self {
            mode: SplitTunnelMode::All,
            targets: HashSet::new(),
        }
    }
}

impl SplitTunnelPolicy {
    /// Returns target packages/apps with self identifier removed to prevent proxy loops.
    pub fn effective_targets(&self, self_id: &str) -> HashSet<String> {
        let mut set = self.targets.clone();
        set.remove(self_id);
        set
    }

    /// Whether this policy results in full routing of all traffic.
    pub fn is_effectively_all(&self, self_id: &str) -> bool {
        match self.mode {
            SplitTunnelMode::All => true,
            SplitTunnelMode::Only => false,
            SplitTunnelMode::Except => self.effective_targets(self_id).is_empty(),
        }
    }

    /// Returns validation error message if policy configuration is unusable.
    pub fn validation_error(&self, self_id: &str) -> Option<String> {
        if self.mode == SplitTunnelMode::Only && self.effective_targets(self_id).is_empty() {
            Some("Choose at least one app, or switch back to All apps".to_string())
        } else {
            None
        }
    }
}
