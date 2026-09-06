//! # Aether Core Integration Tests
//!
//! 1. Evasion/Obfuscation: IKEv2 SA initialization camouflage & WireGuard message header byte masking
//! 2. Routing Engine: PolicyRuleSet multi-criteria matcher (domains, CIDRs, RFC1918, INI parser)
//! 3. Wire Sniffer: Zero-allocation TLS ClientHello SNI and HTTP/1.x plaintext Host sniffing
//! 4. MASQUE Transport: RFC 9297 Capsule framing, VarInt codecs, H3 datagrams, streaming CapsuleParser, and DNS probe builder

use lumicore::evasion::noize_shaper::{mask_wireguard_header, wrap_ikev2};
use lumicore::routing::{Action, Matcher, PolicyRuleSet};
use lumicore::sni::{http_host, sniff_hostname, tls_sni};
use lumicore::transport::{
    build_dns_probe_packet, decode_ip_datagram, decode_varint, encode_address_request,
    encode_capsule, encode_datagram_capsule, encode_ip_datagram, encode_varint,
    looks_like_ip_packet, strip_datagram_context, varint_len, AssignedAddress, Capsule,
    CapsuleParser, CAPSULE_ADDRESS_ASSIGN,
};
use std::net::{IpAddr, Ipv4Addr};

// ============================================================================
// 1. Evasion Plane Tests: IKEv2 Wrapping and WireGuard Header Masking
// ============================================================================

#[test]
fn test_ikev2_wrapping() {
    let raw_payload = b"test wireguard inner packet";
    let wrapped = wrap_ikev2(raw_payload);

    assert_eq!(wrapped.len(), 52 + raw_payload.len());
    // IKEv2 header constants check
    assert_eq!(wrapped[16], 0x21); // Next payload: Security Association (SA)
    assert_eq!(wrapped[17], 0x20); // Version: IKEv2
    assert_eq!(wrapped[18], 0x22); // IKE_SA_INIT exchange type
    assert_eq!(wrapped[19], 0x08); // Initiator flag
    assert_eq!(&wrapped[52..], raw_payload);
}

#[test]
fn test_wireguard_header_masking() {
    // Type 1 (Handshake Init) -> 1 + 0x40 = 0x41
    let msg_init_type = 0x01u8;
    assert_eq!(mask_wireguard_header(msg_init_type), 0x41);

    // Type 2 (Handshake Response) -> 2 + 0x40 = 0x42
    let msg_resp_type = 0x02u8;
    assert_eq!(mask_wireguard_header(msg_resp_type), 0x42);

    // Type 5 (non-standard) should remain untouched
    let msg_other = 0x05u8;
    assert_eq!(mask_wireguard_header(msg_other), 0x05);
}

// ============================================================================
// 2. Policy Routing Plane Tests: Rules, Subnets, and INI Configuration
// ============================================================================

#[test]
fn test_policy_router_matching_and_precedence() {
    let mut rules = PolicyRuleSet::new();
    rules.add_rule(Matcher::DomainSuffix("internal.corp".into()), Action::Direct);
    rules.add_rule(Matcher::DomainFull("blocked.com".into()), Action::Block);
    rules.add_rule(Matcher::Private, Action::Direct);
    rules.add_rule(Matcher::Ports(443, 443), Action::Proxy);

    // Domain suffix match
    assert_eq!(
        rules.evaluate(Some("gitlab.internal.corp"), None, None),
        Action::Direct
    );

    // Domain exact match
    assert_eq!(
        rules.evaluate(Some("blocked.com"), None, None),
        Action::Block
    );

    // Unmatched domain should not trigger
    assert_eq!(
        rules.evaluate(Some("allowed.com"), None, Some(80)),
        Action::Proxy // default action
    );

    // RFC1918 Private IP match
    let private_ip: IpAddr = "192.168.1.50".parse().unwrap();
    assert_eq!(
        rules.evaluate(None, Some(private_ip), None),
        Action::Direct
    );

    let cgnat_ip: IpAddr = "100.64.0.1".parse().unwrap();
    assert_eq!(
        rules.evaluate(None, Some(cgnat_ip), None),
        Action::Direct
    );

    // Public IP with port 443
    let public_ip: IpAddr = "1.1.1.1".parse().unwrap();
    assert_eq!(
        rules.evaluate(None, Some(public_ip), Some(443)),
        Action::Proxy
    );
}

#[test]
fn test_policy_router_from_ini_sections() {
    let ini = r#"
[block]
evil.com
malware.org
198.51.100.0/24

[direct]
lan.company
10.0.0.0/8
"#;

    let rules = PolicyRuleSet::from_ini(ini);
    assert_eq!(rules.evaluate(Some("sub.evil.com"), None, None), Action::Block);
    assert_eq!(rules.evaluate(Some("malware.org"), None, None), Action::Block);

    let blocked_ip: IpAddr = "198.51.100.25".parse().unwrap();
    assert_eq!(rules.evaluate(None, Some(blocked_ip), None), Action::Block);

    let lan_ip: IpAddr = "10.20.30.40".parse().unwrap();
    assert_eq!(rules.evaluate(None, Some(lan_ip), None), Action::Direct);
}

// ============================================================================
// 3. Wire Sniffer Plane Tests: SNI and HTTP Plaintext Sniffing
// ============================================================================

#[test]
fn test_http_host_sniffing() {
    let valid_http = b"GET /v1/status HTTP/1.1\r\nHost: gateway.cloudflare.com:8443\r\nUser-Agent: curl\r\n\r\n";
    assert_eq!(http_host(valid_http).as_deref(), Some("gateway.cloudflare.com"));
    assert_eq!(sniff_hostname(valid_http).as_deref(), Some("gateway.cloudflare.com"));

    let invalid_garbage = b"\x12\x34\x56\x78\x90";
    assert_eq!(http_host(invalid_garbage), None);
}

#[test]
fn test_tls_sni_sniffing() {
    // Construct a synthetic ClientHello with SNI "example.com"
    let host = b"example.com";
    let mut ext = Vec::new();
    ext.extend_from_slice(&0x0000u16.to_be_bytes()); // Server Name Extension type
    let server_name_list_len = 3 + host.len();
    let ext_len = 2 + server_name_list_len;
    ext.extend_from_slice(&(ext_len as u16).to_be_bytes());
    ext.extend_from_slice(&(server_name_list_len as u16).to_be_bytes());
    ext.push(0x00); // HostName type
    ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
    ext.extend_from_slice(host);

    let mut hello = Vec::new();
    hello.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 version
    hello.extend_from_slice(&[0u8; 32]); // Random
    hello.push(0); // Session ID len
    hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // Ciphersuite
    hello.extend_from_slice(&[0x01, 0x00]); // Compression
    hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    hello.extend_from_slice(&ext);

    let mut record = Vec::new();
    record.push(0x16); // Handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
    let handshake_len = 4 + hello.len();
    record.extend_from_slice(&(handshake_len as u16).to_be_bytes());

    record.push(0x01); // ClientHello
    record.push(0x00);
    record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    record.extend_from_slice(&hello);

    let parsed = tls_sni(&record);
    assert_eq!(parsed.as_deref(), Some("example.com"));
    assert_eq!(sniff_hostname(&record).as_deref(), Some("example.com"));
}

// ============================================================================
// 4. MASQUE Transport Plane Tests: Capsules, VarInt, H3 Datagrams & DNS Probing
// ============================================================================

#[test]
fn test_varint_codec() {
    let numbers = [0u64, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, 4611686018427387903];
    for &num in &numbers {
        let mut out = Vec::new();
        encode_varint(num, &mut out);
        assert_eq!(out.len(), varint_len(num));
        let (decoded, consumed) = decode_varint(&out).expect("valid varint");
        assert_eq!(decoded, num);
        assert_eq!(consumed, out.len());
    }
}

#[test]
fn test_h3_datagram_and_capsule_roundtrip() {
    let dummy_packet = vec![0x45, 0x00, 0x00, 0x1c, 0x01, 0x02, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
                            192, 168, 1, 1, 8, 8, 8, 8, 0x00, 0x35, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00];
    let stream_id = 16;

    // H3 Datagram path
    let encoded_datagram = encode_ip_datagram(stream_id, &dummy_packet);
    let decoded_datagram = decode_ip_datagram(&encoded_datagram, stream_id)
        .expect("decode ok")
        .expect("payload present");
    assert_eq!(decoded_datagram, dummy_packet);

    // Capsule streaming parser path
    let mut parser = CapsuleParser::new();
    let capsule_datagram = encode_datagram_capsule(&dummy_packet);
    parser.push(&capsule_datagram);
    let parsed_capsule = parser.next().expect("ok").expect("capsule");

    match parsed_capsule {
        Capsule::Datagram(payload) => assert_eq!(payload, dummy_packet),
        other => panic!("expected Datagram capsule, got {:?}", other),
    }

    // Strip datagram context
    assert_eq!(strip_datagram_context(&dummy_packet), Some(dummy_packet.clone()));
}

#[test]
fn test_address_request_and_assign_capsule() {
    let mut parser = CapsuleParser::new();
    let req = encode_address_request(101, 4, 32);
    parser.push(&req);

    let parsed = parser.next().expect("ok").expect("capsule");
    match parsed {
        Capsule::AddressRequest { request_id, ip_version, prefix_len } => {
            assert_eq!(request_id, 101);
            assert_eq!(ip_version, 4);
            assert_eq!(prefix_len, 32);
        }
        _ => panic!("expected AddressRequest, got {:?}", parsed),
    }
}

#[test]
fn test_address_assign_capsule() {
    let mut parser = CapsuleParser::new();
    let mut payload = Vec::new();
    encode_varint(77, &mut payload);
    payload.push(4); // IPv4
    payload.extend_from_slice(&[10, 0, 0, 5]);
    payload.push(24); // /24
    let capsule_bytes = encode_capsule(CAPSULE_ADDRESS_ASSIGN, &payload);
    parser.push(&capsule_bytes);

    let parsed = parser.next().expect("ok").expect("capsule");
    match parsed {
        Capsule::AddressAssign(addrs) => {
            assert_eq!(addrs.len(), 1);
            assert_eq!(addrs[0], AssignedAddress {
                request_id: 77,
                ip_version: 4,
                address: vec![10, 0, 0, 5],
                prefix_len: 24,
            });
        }
        other => panic!("expected AddressAssign, got {:?}", other),
    }
}


#[test]
fn test_dns_probe_packet_generation() {
    let src_ip = Ipv4Addr::new(172, 16, 0, 10);
    let probe = build_dns_probe_packet(src_ip);

    assert!(looks_like_ip_packet(&probe));
    assert_eq!(probe[0], 0x45); // IPv4
    assert_eq!(probe[9], 17); // UDP
    assert_eq!(&probe[12..16], &src_ip.octets());
    assert_eq!(&probe[16..20], &[8, 8, 8, 8]); // Dest 8.8.8.8
    assert_eq!(&probe[22..24], &53u16.to_be_bytes()); // Dest Port 53
}
