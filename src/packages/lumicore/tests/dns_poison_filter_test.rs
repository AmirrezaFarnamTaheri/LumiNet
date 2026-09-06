//! Unit tests for DNS poison filter, clean resolver vault, and hybrid chained tunnel.

use lumicore::dns::dns_poison_filter::*;
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_is_poisoned_ipv4_detection() {
    // Iranian national filtering redirect page
    assert!(is_poisoned_ipv4(Ipv4Addr::new(10, 10, 34, 1)).is_some());
    assert!(is_poisoned_ipv4(Ipv4Addr::new(10, 10, 34, 254)).is_some());

    // RFC 1918 Class A
    assert!(is_poisoned_ipv4(Ipv4Addr::new(10, 1, 2, 3)).is_some());

    // Loopback
    assert!(is_poisoned_ipv4(Ipv4Addr::new(127, 0, 0, 1)).is_some());

    // Zero / Unspecified
    assert!(is_poisoned_ipv4(Ipv4Addr::new(0, 0, 0, 0)).is_some());

    // RFC 1918 Class C
    assert!(is_poisoned_ipv4(Ipv4Addr::new(192, 168, 1, 1)).is_some());

    // RFC 1918 Class B
    assert!(is_poisoned_ipv4(Ipv4Addr::new(172, 16, 0, 1)).is_some());
    assert!(is_poisoned_ipv4(Ipv4Addr::new(172, 31, 255, 254)).is_some());
    // 172.32.x.x is public, should NOT be flagged as Class B
    assert!(is_poisoned_ipv4(Ipv4Addr::new(172, 32, 0, 1)).is_none());

    // CGNAT
    assert!(is_poisoned_ipv4(Ipv4Addr::new(100, 64, 0, 1)).is_some());
    assert!(is_poisoned_ipv4(Ipv4Addr::new(100, 127, 255, 254)).is_some());
    assert!(is_poisoned_ipv4(Ipv4Addr::new(100, 128, 0, 1)).is_none());

    // Link-local
    assert!(is_poisoned_ipv4(Ipv4Addr::new(169, 254, 1, 1)).is_some());

    // Benchmarking
    assert!(is_poisoned_ipv4(Ipv4Addr::new(198, 18, 0, 1)).is_some());
    assert!(is_poisoned_ipv4(Ipv4Addr::new(198, 19, 255, 254)).is_some());

    // Broadcast & Multicast
    assert!(is_poisoned_ipv4(Ipv4Addr::BROADCAST).is_some());
    assert!(is_poisoned_ipv4(Ipv4Addr::new(224, 0, 0, 1)).is_some());
    assert!(is_poisoned_ipv4(Ipv4Addr::new(239, 255, 255, 250)).is_some());

    // Clean Public IPs
    assert!(is_poisoned_ipv4(Ipv4Addr::new(8, 8, 8, 8)).is_none());
    assert!(is_poisoned_ipv4(Ipv4Addr::new(1, 1, 1, 1)).is_none());
    assert!(is_poisoned_ipv4(Ipv4Addr::new(142, 250, 190, 46)).is_none());
}

#[test]
fn test_build_and_parse_rfc1035_wire_format() {
    let tx_id = 0xABCD;
    let domain = "google.com";

    let query = build_rfc1035_a_query(domain, tx_id).expect("Query build failed");
    assert!(query.len() >= 12 + domain.len() + 2 + 4);

    // Verify transaction ID in bytes 0..2
    let built_id = u16::from_be_bytes([query[0], query[1]]);
    assert_eq!(built_id, tx_id);

    // Verify flags: RD = 1 (0x01, 0x00)
    assert_eq!(query[2], 0x01);
    assert_eq!(query[3], 0x00);

    // Verify QDCOUNT = 1
    assert_eq!(query[4], 0x00);
    assert_eq!(query[5], 0x01);

    // Construct a synthetic valid DNS response packet:
    // Header (12 bytes):
    // ID: 0xABCD
    // Flags: 0x8180 (QR=1, RD=1, RA=1, RCODE=0)
    // QDCOUNT: 1
    // ANCOUNT: 2
    // NSCOUNT: 0, ARCOUNT: 0
    let mut resp = Vec::new();
    resp.extend_from_slice(&tx_id.to_be_bytes());
    resp.extend_from_slice(&[0x81, 0x80]);
    resp.extend_from_slice(&[0x00, 0x01]); // 1 question
    resp.extend_from_slice(&[0x00, 0x02]); // 2 answers
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(&[0x00, 0x00]);

    // Copy Question section from query (bytes 12..end)
    resp.extend_from_slice(&query[12..]);

    // Answer 1: name pointer 0xC00C, TYPE A (0x0001), CLASS IN (0x0001), TTL 300 (0x0000012C), RDLENGTH 4, IP: 142.250.190.46
    resp.extend_from_slice(&[0xC0, 0x0C]);
    resp.extend_from_slice(&[0x00, 0x01]);
    resp.extend_from_slice(&[0x00, 0x01]);
    resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]);
    resp.extend_from_slice(&[0x00, 0x04]);
    resp.extend_from_slice(&[142, 250, 190, 46]);

    // Answer 2: name pointer 0xC00C, TYPE A (0x0001), CLASS IN (0x0001), TTL 300, RDLENGTH 4, IP: 142.250.190.78
    resp.extend_from_slice(&[0xC0, 0x0C]);
    resp.extend_from_slice(&[0x00, 0x01]);
    resp.extend_from_slice(&[0x00, 0x01]);
    resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]);
    resp.extend_from_slice(&[0x00, 0x04]);
    resp.extend_from_slice(&[142, 250, 190, 78]);

    let parsed_ips = parse_rfc1035_a_response(&resp, Some(tx_id)).expect("Parse failed");
    assert_eq!(parsed_ips.len(), 2);
    assert_eq!(parsed_ips[0], Ipv4Addr::new(142, 250, 190, 46));
    assert_eq!(parsed_ips[1], Ipv4Addr::new(142, 250, 190, 78));
}

#[test]
fn test_dns_vault_store_lifecycle() {
    let mut vault = DnsVaultStore::new();

    let cf = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let google = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    let poisoned = IpAddr::V4(Ipv4Addr::new(10, 10, 34, 1));

    vault.update_record(cf, 42, true, "Cloudflare DNS");
    vault.update_record(google, 28, true, "Google Public DNS");
    vault.update_record(poisoned, 5, false, "Poisoned Resolver");

    let clean = vault.rank_clean_dns();
    assert_eq!(clean.len(), 2);
    // Google has lower latency (28ms vs 42ms)
    assert_eq!(clean[0].ip, google);
    assert_eq!(clean[1].ip, cf);

    let fastest = vault.get_fastest_clean().expect("Expected fastest");
    assert_eq!(fastest.ip, google);
    assert_eq!(fastest.latency_ms, 28);

    // Serialization / Deserialization
    let json = vault.to_json().expect("Serialization failed");
    let loaded_vault = DnsVaultStore::from_json(&json).expect("Deserialization failed");
    assert_eq!(loaded_vault.records.len(), 3);
    assert_eq!(loaded_vault.get_fastest_clean().unwrap().ip, google);
}

#[test]
fn test_hybrid_chained_tunnel_config() {
    let config = HybridChainedTunnelConfig {
        local_bridge_port: 1819,
        local_bridge_protocol: "socks5".to_string(),
        upstream_core_type: "masque_aether".to_string(),
        downstream_node_tag: "vless_sg_node".to_string(),
        upstream_listen_host: "127.0.0.1".to_string(),
    };

    let compiled = config.generate_chained_dialer_config();
    assert!(compiled.is_object());

    let outbounds = compiled["outbounds"].as_array().expect("Expected outbounds array");
    assert_eq!(outbounds[0]["type"], "socks5");
    assert_eq!(outbounds[0]["server_port"], 1819);
    assert_eq!(outbounds[0]["tag"], "hybrid_upstream_bridge");

    let chain_meta = &compiled["chain_metadata"];
    assert_eq!(chain_meta["upstream_core"], "masque_aether");
    assert_eq!(chain_meta["dialer_proxy_tag"], "hybrid_upstream_bridge");
    assert_eq!(chain_meta["target_node"], "vless_sg_node");
}
