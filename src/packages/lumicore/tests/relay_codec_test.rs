use lumicore::relay::relay_stream_codec::{RelayNetwork, RelayStreamHeader};
use lumicore::relay::quota_tracker::QuotaTracker;

#[test]
fn test_relay_stream_v1_ascii_tcp() {
    let header = RelayStreamHeader::new(RelayNetwork::Tcp, "104.21.5.12", 80);
    let wire = header.encode_v1();
    assert_eq!(wire, b"tcp@104.21.5.12$80\r");

    let (parsed, consumed) = RelayStreamHeader::decode_v1(&wire).expect("parse v1 tcp");
    assert_eq!(consumed, wire.len());
    assert_eq!(parsed.network, RelayNetwork::Tcp);
    assert_eq!(parsed.host, "104.21.5.12");
    assert_eq!(parsed.port, 80);
}

#[test]
fn test_relay_stream_v1_ascii_udp() {
    let header = RelayStreamHeader::new(RelayNetwork::Udp, "1.0.0.1", 53);
    let wire = header.encode_v1();
    assert_eq!(wire, b"udp@1.0.0.1$53\r");

    let (parsed, consumed) = RelayStreamHeader::decode_v1(&wire).expect("parse v1 udp");
    assert_eq!(consumed, wire.len());
    assert_eq!(parsed.network, RelayNetwork::Udp);
    assert_eq!(parsed.host, "1.0.0.1");
    assert_eq!(parsed.port, 53);
}

#[test]
fn test_relay_stream_v2_binary() {
    let header = RelayStreamHeader::new(RelayNetwork::Tcp, "origin.gateway.test", 443);
    let wire = header.encode_v2();

    let (parsed, consumed) = RelayStreamHeader::decode_v2(&wire).expect("parse v2 binary");
    assert_eq!(consumed, wire.len());
    assert_eq!(parsed.network, RelayNetwork::Tcp);
    assert_eq!(parsed.host, "origin.gateway.test");
    assert_eq!(parsed.port, 443);
}

#[test]
fn test_apps_script_quota_tracker_budget() {
    let mut tracker = QuotaTracker::with_limits(3600, 2);
    tracker.register("script-deploy-1");

    assert_eq!(tracker.select_best_account(1000), Some("script-deploy-1".into()));

    tracker.record_outcome("script-deploy-1", 1000, 500, 1500, true);
    tracker.record_outcome("script-deploy-1", 1010, 500, 1500, true);

    // After 2 requests, limit reached
    assert_eq!(tracker.select_best_account(1020), None);

    // After window reset, available again
    assert_eq!(tracker.select_best_account(5000), Some("script-deploy-1".into()));
}
