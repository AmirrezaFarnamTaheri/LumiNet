use lumicore::diagnostics::tunnel_health_evaluator::{
    evaluate_tunnel_health, EncryptionLevel, FecProfileTier, TunnelHealthVerdict, TunnelMetrics,
};

#[test]
fn test_fec_profile_tiers() {
    let none = FecProfileTier::from_str("none").unwrap().to_profile();
    assert!(!none.enabled);
    assert_eq!(none.group_size, 8);

    let cons = FecProfileTier::from_str("conservative").unwrap().to_profile();
    assert!(cons.enabled);
    assert_eq!(cons.group_size, 8);
    assert_eq!(cons.overhead_percent, 15);

    let bal = FecProfileTier::from_str("balanced").unwrap().to_profile();
    assert!(bal.enabled);
    assert_eq!(bal.group_size, 12);
    assert_eq!(bal.overhead_percent, 25);

    let agg = FecProfileTier::from_str("aggressive").unwrap().to_profile();
    assert!(agg.enabled);
    assert_eq!(agg.group_size, 16);
    assert_eq!(agg.overhead_percent, 40);
}

#[test]
fn test_encryption_levels() {
    let std = EncryptionLevel::from_str("standard").unwrap();
    assert_eq!(std.method_id(), 3);
    assert_eq!(std.cipher_name(), "aes-128-gcm");

    let strong = EncryptionLevel::from_str("strong").unwrap();
    assert_eq!(strong.method_id(), 4);
    assert_eq!(strong.cipher_name(), "aes-192-gcm");

    let max = EncryptionLevel::from_str("maximum").unwrap();
    assert_eq!(max.method_id(), 5);
    assert_eq!(max.cipher_name(), "aes-256-gcm");
}

#[test]
fn test_tunnel_health_evaluator_states() {
    // 1. Disconnected
    let report = evaluate_tunnel_health(None, "disconnected", 0.0, 5000);
    assert_eq!(report.verdict, TunnelHealthVerdict::Disconnected);

    // 2. Starting
    let report = evaluate_tunnel_health(None, "connecting", 0.0, 5000);
    assert_eq!(report.verdict, TunnelHealthVerdict::Starting);

    // 3. WaitingForTraffic
    let mut metrics = TunnelMetrics {
        uptime_seconds: 5,
        bytes_in: 0,
        bytes_out: 500,
        packets_in: 0,
        packets_out: 2,
        rtt_ms: None,
        packet_loss_percent: 0.0,
        last_packet_age_ms: 1000,
    };
    let report = evaluate_tunnel_health(Some(&metrics), "connected", 0.0, 5000);
    assert_eq!(report.verdict, TunnelHealthVerdict::WaitingForTraffic);

    // 4. Broken (packets_in == 0 and last_packet_age > idle_timeout)
    metrics.last_packet_age_ms = 6000;
    let report = evaluate_tunnel_health(Some(&metrics), "connected", 0.0, 5000);
    assert_eq!(report.verdict, TunnelHealthVerdict::Broken);

    // 5. Working
    let healthy_metrics = TunnelMetrics {
        uptime_seconds: 60,
        bytes_in: 50000,
        bytes_out: 30000,
        packets_in: 120,
        packets_out: 100,
        rtt_ms: Some(45),
        packet_loss_percent: 0.5,
        last_packet_age_ms: 150,
    };
    let report = evaluate_tunnel_health(Some(&healthy_metrics), "connected", 0.0, 5000);
    assert_eq!(report.verdict, TunnelHealthVerdict::Working);

    // 6. Degraded (loss > 35% or RTT > 1200ms)
    let degraded_metrics = TunnelMetrics {
        uptime_seconds: 120,
        bytes_in: 50000,
        bytes_out: 30000,
        packets_in: 120,
        packets_out: 100,
        rtt_ms: Some(1500),
        packet_loss_percent: 40.0,
        last_packet_age_ms: 200,
    };
    let report = evaluate_tunnel_health(Some(&degraded_metrics), "connected", 0.0, 5000);
    assert_eq!(report.verdict, TunnelHealthVerdict::Degraded);
}
