use std::collections::HashSet;
use std::time::Duration;
use lumicore::diagnostics::{
    format_bytes, format_rate, SplitTunnelMode, SplitTunnelPolicy, TrafficMeterSmoother,
};

#[test]
fn test_traffic_meter_smoothing() {
    let mut meter = TrafficMeterSmoother::new();
    meter.start(1000, 2000);

    // After 1 second, rx climbed by 102400 (100 KB/s), tx by 51200 (50 KB/s)
    let s1 = meter.sample_now(1000 + 102400, 2000 + 51200, Duration::from_secs(1));
    assert_eq!(s1.received_bytes, 102400);
    assert_eq!(s1.sent_bytes, 51200);
    assert_eq!(s1.download_bytes_per_sec, 102400);
    assert_eq!(s1.upload_bytes_per_sec, 51200);

    // After another second, another 102400 rx, but tx is 0
    // smoothed_down should stay 102400 (0.4 * 102400 + 0.6 * 102400 = 102400)
    // smoothed_up should decay (0.4 * 51200 + 0.6 * 0 = 20480)
    let s2 = meter.sample_now(1000 + 204800, 2000 + 51200, Duration::from_secs(1));
    assert_eq!(s2.download_bytes_per_sec, 102400);
    assert_eq!(s2.upload_bytes_per_sec, 20480);
}

#[test]
fn test_format_bytes_and_rate() {
    assert_eq!(format_bytes(500), "500 B");
    assert_eq!(format_bytes(1536), "1.5 KB");
    assert_eq!(format_bytes(10 * 1024 * 1024), "10 MB");
    assert_eq!(format_bytes(1500 * 1024 * 1024), "1.5 GB");

    assert_eq!(format_rate(10 * 1024 * 1024), "10 MB/s");
}

#[test]
fn test_split_tunnel_policy() {
    let mut targets = HashSet::new();
    targets.insert("com.example.browser".to_string());
    targets.insert("com.luminet.vpn".to_string());

    let policy = SplitTunnelPolicy {
        mode: SplitTunnelMode::Only,
        targets,
    };

    // Self package must be excluded
    let effective = policy.effective_targets("com.luminet.vpn");
    assert_eq!(effective.len(), 1);
    assert!(effective.contains("com.example.browser"));
    assert!(!effective.contains("com.luminet.vpn"));

    // Validation passes with 1 target
    assert!(policy.validation_error("com.luminet.vpn").is_none());

    // Validation fails if only target was self
    let mut self_only = HashSet::new();
    self_only.insert("com.luminet.vpn".to_string());
    let policy_empty = SplitTunnelPolicy {
        mode: SplitTunnelMode::Only,
        targets: self_only,
    };
    assert!(policy_empty.validation_error("com.luminet.vpn").is_some());
}
