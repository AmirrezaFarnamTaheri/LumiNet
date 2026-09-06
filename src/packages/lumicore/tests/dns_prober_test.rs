use lumicore::scanner::{
    format_tunnel_realism_qname, is_transparent_proxy_detected, verify_nxdomain_ratio,
    TunnelTestResult, DEFAULT_TUNNEL_SCORE_THRESHOLD, TRANSPARENT_PROXY_TEST_IPS,
};
use std::net::Ipv4Addr;

#[test]
fn test_transparent_proxy_detection() {
    // When no test IP responds, transparent proxy is not detected
    let detected = is_transparent_proxy_detected(|_ip| false);
    assert!(!detected);

    // When one RFC 5737 test IP responds (e.g. 198.51.100.1 intercepted by ISP), it is detected
    let detected_intercept = is_transparent_proxy_detected(|ip| ip == Ipv4Addr::new(198, 51, 100, 1));
    assert!(detected_intercept);

    assert_eq!(TRANSPARENT_PROXY_TEST_IPS.len(), 3);
}

#[test]
fn test_tunnel_score_and_qualification() {
    let empty = TunnelTestResult::default();
    assert_eq!(empty.score(), 0);
    assert!(!empty.is_qualified(DEFAULT_TUNNEL_SCORE_THRESHOLD));
    assert!(!empty.is_stable());

    let qualified = TunnelTestResult {
        ns_support: true,
        txt_support: true,
        random_sub: false,
        tunnel_realism: false,
        edns0_support: true,
        edns_max_payload: 1232,
        nxdomain_correct: false,
    };
    assert_eq!(qualified.score(), 3);
    assert!(qualified.is_qualified(DEFAULT_TUNNEL_SCORE_THRESHOLD));
    assert!(!qualified.is_stable());

    let full = TunnelTestResult {
        ns_support: true,
        txt_support: true,
        random_sub: true,
        tunnel_realism: true,
        edns0_support: true,
        edns_max_payload: 1232,
        nxdomain_correct: true,
    };
    assert_eq!(full.score(), 6);
    assert!(full.is_qualified(DEFAULT_TUNNEL_SCORE_THRESHOLD));
    assert!(full.is_stable());
}

#[test]
fn test_format_tunnel_realism_qname() {
    let payload = b"Hello, DNS Tunneling World!";
    let qname = format_tunnel_realism_qname(payload, "t.example.org");

    assert!(qname.ends_with(".t.example.org"));
    let labels: Vec<&str> = qname.split('.').collect();
    // Labels before t.example.org must be <= 57 bytes
    for label in &labels[..labels.len() - 3] {
        assert!(label.len() <= 57);
        assert!(!label.contains('=')); // Base32 without padding
    }
}

#[test]
fn test_verify_nxdomain_ratio() {
    // 2 out of 3 = 66.6% -> passes
    assert!(verify_nxdomain_ratio(2, 3));
    // 3 out of 3 = 100% -> passes
    assert!(verify_nxdomain_ratio(3, 3));
    // 1 out of 3 = 33.3% -> fails (indicates DNS poisoning/forgery)
    assert!(!verify_nxdomain_ratio(1, 3));
    // 0 out of 3 -> fails
    assert!(!verify_nxdomain_ratio(0, 3));
}
