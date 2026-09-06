//! Integration and unit tests for proxy node identity, deduplication, and structural filtering.

use lumicore::proxy::node_identity::*;

#[test]
fn test_dummy_proxy_detection() {
    assert!(is_dummy_proxy("vless://00000000-0000-0000-0000-000000000000@example.com:443#test"));
    assert!(is_dummy_proxy("vmess://dummy?app%20not%20supported=true"));
    assert!(is_dummy_proxy("trojan://pass@example.com:443#app not supported"));
    assert!(is_dummy_proxy("proxies: []"));
    assert!(!is_dummy_proxy("vless://b0341a94-4b5b-4c28-98e3-0ecdfb008d51@example.com:443?security=tls#node1"));
}

#[test]
fn test_invalid_port_validation() {
    assert!(is_invalid_port(0));
    assert!(is_invalid_port(65536));
    assert!(is_invalid_port(70000));
    assert!(!is_invalid_port(80));
    assert!(!is_invalid_port(443));
    assert!(!is_invalid_port(65535));
}

#[test]
fn test_unroutable_server_detection() {
    assert!(is_unroutable_server("127.0.0.1"));
    assert!(is_unroutable_server("127.0.0.53"));
    assert!(is_unroutable_server("0.0.0.0"));
    assert!(is_unroutable_server("169.254.1.2"));
    assert!(is_unroutable_server("224.0.0.1"));
    assert!(is_unroutable_server("240.0.0.5"));
    assert!(is_unroutable_server("::1"));
    assert!(is_unroutable_server("[::1]"));
    assert!(is_unroutable_server("fe80::1"));

    // Routable public IPs and hostnames
    assert!(!is_unroutable_server("1.1.1.1"));
    assert!(!is_unroutable_server("8.8.8.8"));
    assert!(!is_unroutable_server("cloudflare.com"));
    assert!(!is_unroutable_server("proxy.example.org"));
}

#[test]
fn test_structurally_invalid_server_detection() {
    // Valid hosts
    assert!(!is_structurally_invalid_server("example.com"));
    assert!(!is_structurally_invalid_server("sub.domain.co.uk"));
    assert!(!is_structurally_invalid_server("1.1.1.1"));
    assert!(!is_structurally_invalid_server("[2606:4700:4700::1111]"));

    // Structurally invalid hosts
    assert!(is_structurally_invalid_server(""));
    assert!(is_structurally_invalid_server("masir_sefid")); // single label without dot
    assert!(is_structurally_invalid_server("black_raven_ir")); // single label without dot
    assert!(is_structurally_invalid_server("https://github.com/test/repo")); // full URL
    assert!(is_structurally_invalid_server("example.com:443")); // port residue on hostname
    assert!(is_structurally_invalid_server("test host.com")); // whitespace
    assert!(is_structurally_invalid_server("test/sub.com")); // slash
    assert!(is_structurally_invalid_server("-badlabel.com")); // starts with hyphen
}

#[test]
fn test_invalid_uuid_rules() {
    // Protocols where UUID rule applies (vless, vmess, tuic)
    assert!(is_invalid_uuid("", "vless"));
    assert!(is_invalid_uuid("00000000-0000-0000-0000-000000000000", "vless"));
    assert!(is_invalid_uuid("00000000000000000000000000000000", "vmess"));

    // Valid canonical 36-char UUID
    assert!(!is_invalid_uuid("b0341a94-4b5b-4c28-98e3-0ecdfb008d51", "vless"));
    // Valid compact 32-char hex UUID
    assert!(!is_invalid_uuid("f23bb427c1f94373876c2f43e9f790f3", "vmess"));

    // Legitimate custom strings < 30 bytes
    assert!(!is_invalid_uuid("@free_conf_iran", "vless"));
    assert!(!is_invalid_uuid("13094", "vless"));
    assert!(!is_invalid_uuid("AlfredConfig", "vmess"));

    // Overlong string >= 30 bytes that is not UUID
    assert!(is_invalid_uuid("this-is-a-very-long-custom-string-exceeding-thirty-bytes", "vless"));

    // Non-UUID protocols: arbitrary passwords allowed
    assert!(!is_invalid_uuid("any_arbitrary_long_password_for_shadowsocks_or_trojan", "shadowsocks"));
    assert!(!is_invalid_uuid("00000000-0000-0000-0000-000000000000", "trojan"));
}

#[test]
fn test_compute_node_dedup_key_and_stable_tag() {
    let vless = "vless://b0341a94-4b5b-4c28-98e3-0ecdfb008d51@1.2.3.4:443?security=tls&sni=mycdn.com&type=ws&host=mycdn.com&path=%2Fws#MyNode";
    let key1 = compute_node_dedup_key(vless);
    let tag1 = compute_stable_node_tag(vless);

    // Dedup key should normalize and contain endpoint fronting
    assert!(key1.contains("1.2.3.4"));
    assert!(key1.contains("ep=mycdn.com"));
    assert!(key1.contains("b0341a94-4b5b-4c28-98e3-0ecdfb008d51"));
    assert_eq!(tag1.len(), 6);
    assert!(tag1.chars().all(|c| c.is_ascii_hexdigit()));

    // Different remark must produce the exact same tag (position/remark immunity)
    let vless2 = "vless://b0341a94-4b5b-4c28-98e3-0ecdfb008d51@1.2.3.4:443?security=tls&sni=mycdn.com&type=ws&host=mycdn.com&path=%2Fws#DifferentRemark";
    let tag2 = compute_stable_node_tag(vless2);
    assert_eq!(tag1, tag2);

    // Shadowsocks SIP002 vs legacy normalization
    let ss_uri = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@104.28.1.1:8388?plugin=obfs-local#SS-Node";
    let ss_key = compute_node_dedup_key(ss_uri);
    assert!(ss_key.starts_with("ss:sip002:"));
    assert!(ss_key.contains("104.28.1.1:8388"));
}

#[test]
fn test_country_code_to_flag() {
    assert_eq!(country_code_to_flag("US"), Some("🇺🇸".to_string()));
    assert_eq!(country_code_to_flag("de"), Some("🇩🇪".to_string()));
    assert_eq!(country_code_to_flag("IR"), Some("🇮🇷".to_string()));
    assert_eq!(country_code_to_flag("FR"), Some("🇫🇷".to_string()));
    assert_eq!(country_code_to_flag("GB"), Some("🇬🇧".to_string()));
    assert_eq!(country_code_to_flag("XYZ"), None);
    assert_eq!(country_code_to_flag("12"), None);
}
