//! Integration tests for Project 07 (Edge Worker Panel, NAT64 Prefix Embedding, and Edge WS Protocols).

use lumicore::proxy::edge_websocket_codec::{
    build_vless_response_header, compute_trojan_sha224_hash, decode_early_data,
    parse_trojan_ws_header, parse_vless_ws_header, EdgeCodecError, TargetAddress,
};
use lumicore::routing::nat64_prefix::{
    extract_nat64, format_bracketed_ipv6, synthesize_nat64, FallbackMode, Nat64Router,
    OutboundRoute, RFC6052_WELL_KNOWN_PREFIX,
};
use std::net::{Ipv4Addr, Ipv6Addr};

#[test]
fn test_nat64_rfc6052_prefix_embedding() {
    let target_v4 = Ipv4Addr::new(198, 51, 100, 24);
    let synthesized_v6 = synthesize_nat64(target_v4, &RFC6052_WELL_KNOWN_PREFIX);

    // Well-Known Prefix: 64:ff9b::
    // 198.51 (0xc633), 100.24 (0x6418)
    assert_eq!(
        synthesized_v6,
        Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0xc633, 0x6418)
    );

    // Extraction must recover original IPv4
    let recovered_v4 = extract_nat64(&synthesized_v6, &RFC6052_WELL_KNOWN_PREFIX);
    assert_eq!(recovered_v4, Some(target_v4));

    // Formatted URI bracket string
    let bracketed = format_bracketed_ipv6(&synthesized_v6);
    assert!(bracketed.starts_with('[') && bracketed.ends_with(']'));
}

#[test]
fn test_nat64_custom_prefix_embedding() {
    let custom_pfx: Ipv6Addr = "2606:4700::".parse().unwrap();
    let target_v4 = Ipv4Addr::new(104, 21, 5, 88);
    let syn_v6 = synthesize_nat64(target_v4, &custom_pfx);

    // 104.21 -> 0x6815, 5.88 -> 0x0558
    assert_eq!(
        syn_v6,
        Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0x6815, 0x0558)
    );

    let recovered = extract_nat64(&syn_v6, &custom_pfx);
    assert_eq!(recovered, Some(target_v4));
}

#[test]
fn test_nat64_router_dynamic_fallback() {
    let pfx_router = Nat64Router::default();
    let route = pfx_router.route_outbound(Ipv4Addr::new(1, 1, 1, 1));
    match route {
        OutboundRoute::SynthesizedIpv6(v6) => {
            assert_eq!(v6.segments()[6], 0x0101);
            assert_eq!(v6.segments()[7], 0x0101);
        }
        _ => panic!("Expected SynthesizedIpv6"),
    }

    let proxy_router = Nat64Router::new(
        FallbackMode::ProxyIp,
        RFC6052_WELL_KNOWN_PREFIX,
        vec!["104.16.2.1:443".into()],
    );
    let route2 = proxy_router.route_outbound(Ipv4Addr::new(1, 1, 1, 1));
    assert_eq!(route2, OutboundRoute::ProxyHop("104.16.2.1:443".into()));
}

#[test]
fn test_vless_ws_protocol_parsing_and_response() {
    let uuid = [0x42u8; 16];
    let mut packet = Vec::new();
    packet.push(0x00); // version
    packet.extend_from_slice(&uuid); // 16 bytes uuid
    packet.push(0x00); // addon length
    packet.push(0x01); // command TCP
    packet.extend_from_slice(&8443u16.to_be_bytes()); // port 8443
    packet.push(0x02); // Domain address
    let domain = b"api.example.com";
    packet.push(domain.len() as u8);
    packet.extend_from_slice(domain);
    packet.extend_from_slice(b"HTTP/1.1 GET /feed\r\n\r\n");

    let header = parse_vless_ws_header(&packet, &uuid).expect("vless header should parse");
    assert_eq!(header.version, 0x00);
    assert_eq!(header.target_port, 8443);
    assert_eq!(
        header.target_addr,
        TargetAddress::Domain("api.example.com".into())
    );
    assert!(!header.is_udp);
    assert_eq!(
        &packet[header.payload_offset..],
        b"HTTP/1.1 GET /feed\r\n\r\n"
    );

    let resp_header = build_vless_response_header(0x00);
    assert_eq!(resp_header, [0x00, 0x00]);
}

#[test]
fn test_vless_ws_negative_cases() {
    let uuid = [0x01u8; 16];
    let wrong_uuid = [0x02u8; 16];

    let mut packet = Vec::new();
    packet.push(0x00);
    packet.extend_from_slice(&wrong_uuid);
    packet.push(0x00);
    packet.push(0x01);
    packet.extend_from_slice(&80u16.to_be_bytes());
    packet.push(0x01);
    packet.extend_from_slice(&[10, 0, 0, 1]);

    // Wrong UUID rejection
    assert_eq!(
        parse_vless_ws_header(&packet, &uuid),
        Err(EdgeCodecError::InvalidUser)
    );

    // Truncated packet rejection
    assert_eq!(
        parse_vless_ws_header(&packet[..10], &uuid),
        Err(EdgeCodecError::BufferTooShort)
    );
}

#[test]
fn test_trojan_ws_protocol_parsing() {
    let password = "super-secure-trojan-edge-pass";
    let sha224_hex = compute_trojan_sha224_hash(password);
    assert_eq!(sha224_hex.len(), 56);

    let mut packet = Vec::new();
    packet.extend_from_slice(sha224_hex.as_bytes()); // 56 bytes
    packet.extend_from_slice(&[0x0d, 0x0a]); // CRLF delimiter

    // SOCKS5 request payload: CONNECT, IPv4, 1.1.1.1:443
    packet.push(0x01); // CONNECT
    packet.push(0x01); // IPv4
    packet.extend_from_slice(&[1, 1, 1, 1]);
    packet.extend_from_slice(&443u16.to_be_bytes());
    packet.extend_from_slice(&[0x0d, 0x0a]); // CRLF after port
    packet.extend_from_slice(b"TLS_CLIENT_HELLO_DATA");

    let header = parse_trojan_ws_header(&packet, &sha224_hex).expect("trojan header should parse");
    assert_eq!(
        header.target_addr,
        TargetAddress::Ipv4(Ipv4Addr::new(1, 1, 1, 1))
    );
    assert_eq!(header.target_port, 443);
    assert_eq!(&packet[header.payload_offset..], b"TLS_CLIENT_HELLO_DATA");
}

#[test]
fn test_trojan_ws_negative_cases() {
    let correct_hash = compute_trojan_sha224_hash("pass1");
    let mut bad_packet = Vec::new();
    bad_packet.extend_from_slice(b"0123456789abcdef0123456789abcdef0123456789abcdef01234567"); // 56 fake bytes
    bad_packet.extend_from_slice(&[0x0d, 0x0a]);
    bad_packet.push(0x01);
    bad_packet.push(0x01);
    bad_packet.extend_from_slice(&[8, 8, 8, 8]);
    bad_packet.extend_from_slice(&53u16.to_be_bytes());
    bad_packet.extend_from_slice(&[0x0d, 0x0a]);

    // Invalid password hash
    assert_eq!(
        parse_trojan_ws_header(&bad_packet, &correct_hash),
        Err(EdgeCodecError::InvalidPasswordHash)
    );
}

#[test]
fn test_early_data_urlsafe_decoding() {
    let original = b"early websocket transport data";
    use base64::Engine;
    let url_safe_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(original);

    let decoded = decode_early_data(&url_safe_b64).expect("early data should decode");
    assert_eq!(decoded, original);
}
