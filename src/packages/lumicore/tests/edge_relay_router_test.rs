use lumicore::transport::{
    EdgeRelayConfig, EdgeRelayRouter, EdgeRoutingDecision, EdgeRouteTarget, EdgeRelayNetwork,
};
use std::net::IpAddr;

#[test]
fn test_edge_relay_direct_route_for_normal_traffic() {
    let router = EdgeRelayRouter::default();
    let target = EdgeRouteTarget {
        network: EdgeRelayNetwork::Tcp,
        host: "example.com".to_string(),
        port: 80,
        resolved_ip: Some("93.184.216.34".parse().unwrap()),
    };

    let decision = router.decide_route(&target, None);
    assert_eq!(
        decision,
        EdgeRoutingDecision::Direct {
            host: "example.com".to_string(),
            port: 80,
        }
    );
}

#[test]
fn test_edge_relay_chained_route_for_cf_ip() {
    let router = EdgeRelayRouter::default();
    let target = EdgeRouteTarget {
        network: EdgeRelayNetwork::Tcp,
        host: "cloudflare.com".to_string(),
        port: 443,
        resolved_ip: Some("104.16.132.229".parse().unwrap()), // in 104.16.0.0/13
    };

    let decision = router.decide_route(&target, Some(1));
    assert_eq!(
        decision,
        EdgeRoutingDecision::RelayChained {
            relay_host: "relay2.bepass.org".to_string(),
            relay_port: 6666,
            delimiter_header: "tcp@cloudflare.com$443\r\n".to_string(),
        }
    );
}

#[test]
fn test_edge_relay_chained_route_for_udp() {
    let router = EdgeRelayRouter::default();
    let target = EdgeRouteTarget {
        network: EdgeRelayNetwork::Udp,
        host: "8.8.8.8".to_string(),
        port: 53,
        resolved_ip: Some("8.8.8.8".parse().unwrap()),
    };

    let decision = router.decide_route(&target, Some(2));
    assert_eq!(
        decision,
        EdgeRoutingDecision::RelayChained {
            relay_host: "relay3.bepass.org".to_string(),
            relay_port: 6666,
            delimiter_header: "udp@8.8.8.8$53\r\n".to_string(),
        }
    );
}

#[test]
fn test_session_hash_relay_selection() {
    let router = EdgeRelayRouter::default();

    assert_eq!(router.select_relay_endpoint(Some(0)).0, "relay1.bepass.org");
    assert_eq!(router.select_relay_endpoint(Some(1)).0, "relay2.bepass.org");
    assert_eq!(router.select_relay_endpoint(Some(2)).0, "relay3.bepass.org");
    assert_eq!(router.select_relay_endpoint(Some(3)).0, "relay1.bepass.org");
    assert_eq!(router.select_relay_endpoint(None).0, "relay1.bepass.org");
}

#[test]
fn test_fallback_route_generation() {
    let router = EdgeRelayRouter::default();
    let target = EdgeRouteTarget {
        network: EdgeRelayNetwork::Tcp,
        host: "api.service.io".to_string(),
        port: 443,
        resolved_ip: None,
    };

    let fallback = router.build_fallback_relay_route(&target, Some(4));
    assert_eq!(
        fallback,
        EdgeRoutingDecision::RelayChained {
            relay_host: "relay2.bepass.org".to_string(),
            relay_port: 6666,
            delimiter_header: "tcp@api.service.io$443\r\n".to_string(),
        }
    );
}

#[test]
fn test_doh_a_query_builder() {
    let query = EdgeRelayRouter::build_doh_a_query("example.com");

    // Check Transaction ID (0x1234)
    assert_eq!(query[0], 0x12);
    assert_eq!(query[1], 0x34);

    // Standard query flags (0x0100)
    assert_eq!(query[2], 0x01);
    assert_eq!(query[3], 0x00);

    // Questions: 1
    assert_eq!(query[4], 0x00);
    assert_eq!(query[5], 0x01);

    // QNAME: 7 "example" 3 "com" 0
    let expected_qname = b"\x07example\x03com\x00";
    assert_eq!(&query[12..12 + expected_qname.len()], expected_qname);

    // Trailing Type A (0x0001) and Class IN (0x0001)
    let tail = &query[12 + expected_qname.len()..];
    assert_eq!(tail, &[0x00, 0x01, 0x00, 0x01]);
}
