use lumicore::evasion::multi_strategy_fragmenter::{
    extract_sni, fixed_chunks, fragment_packet, locate_sni, rewrite_final_mask_tls_hello,
    rewrite_final_mask_writes, split_at, split_tls_record, CarrierEdgeProfile,
    CarrierRouteSelector, FinalMaskSettings, FragmentStrategy,
};
use std::time::Duration;

/// Helper to build a minimal valid TLS 1.2/1.3 ClientHello with SNI extension.
fn build_test_client_hello(sni_host: &str) -> Vec<u8> {
    let host_bytes = sni_host.as_bytes();
    let mut pkt = Vec::new();

    // TLS Record Header: Handshake (0x16), TLS 1.0 (0x03, 0x01), Length placeholder
    pkt.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x00]);

    let handshake_start = pkt.len();
    // Handshake Header: ClientHello (0x01), Handshake Length placeholder (3 bytes)
    pkt.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

    // Version: TLS 1.2 (0x03, 0x03)
    pkt.extend_from_slice(&[0x03, 0x03]);

    // Random: 32 bytes
    pkt.extend_from_slice(&[0x42; 32]);

    // Session ID: len 0
    pkt.push(0x00);

    // Cipher Suites: 2 bytes len + 2 suites (4 bytes)
    pkt.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]);

    // Compression: len 1 + null compression (0x00)
    pkt.extend_from_slice(&[0x01, 0x00]);

    // Extensions
    let ext_len_pos = pkt.len();
    pkt.extend_from_slice(&[0x00, 0x00]); // placeholder

    let ext_start = pkt.len();

    // Extension: Server Name Indication (0x0000)
    let sni_ext_len = 2 + 1 + 2 + host_bytes.len(); // list_len(2) + name_type(1) + name_len(2) + host
    pkt.extend_from_slice(&[
        0x00, 0x00,
        ((sni_ext_len >> 8) & 0xff) as u8,
        (sni_ext_len & 0xff) as u8,
    ]);

    let list_len = 1 + 2 + host_bytes.len();
    pkt.extend_from_slice(&[
        ((list_len >> 8) & 0xff) as u8,
        (list_len & 0xff) as u8,
        0x00, // host_name type
        ((host_bytes.len() >> 8) & 0xff) as u8,
        (host_bytes.len() & 0xff) as u8,
    ]);
    pkt.extend_from_slice(host_bytes);

    // Fill extensions length
    let ext_len = pkt.len() - ext_start;
    pkt[ext_len_pos] = ((ext_len >> 8) & 0xff) as u8;
    pkt[ext_len_pos + 1] = (ext_len & 0xff) as u8;

    // Fill handshake length
    let hs_len = pkt.len() - handshake_start - 4;
    pkt[handshake_start + 1] = ((hs_len >> 16) & 0xff) as u8;
    pkt[handshake_start + 2] = ((hs_len >> 8) & 0xff) as u8;
    pkt[handshake_start + 3] = (hs_len & 0xff) as u8;

    // Fill record length
    let rec_len = pkt.len() - 5;
    pkt[3] = ((rec_len >> 8) & 0xff) as u8;
    pkt[4] = (rec_len & 0xff) as u8;

    pkt
}

#[test]
fn test_sni_locating_and_extraction() {
    let client_hello = build_test_client_hello("speedtest.net");
    let located = locate_sni(&client_hello);
    assert!(located.is_some(), "Must locate SNI in valid ClientHello");

    let (offset, len) = located.unwrap();
    assert_eq!(&client_hello[offset..offset + len], b"speedtest.net");

    let extracted = extract_sni(&client_hello);
    assert_eq!(extracted, Some("speedtest.net".to_string()));
}

#[test]
fn test_ten_fragmentation_strategies() {
    let client_hello = build_test_client_hello("speedtest.net");
    let settings = FinalMaskSettings::default();

    // 1. Raw
    let raw = fragment_packet(&client_hello, FragmentStrategy::Raw, &settings);
    assert_eq!(raw.len(), 1);
    assert_eq!(raw[0], client_hello);

    // 2. Full5
    let full5 = fragment_packet(&client_hello, FragmentStrategy::Full5, &settings);
    assert!(full5.len() > 1);
    assert_eq!(full5[0].len(), 5);
    let reconstructed: Vec<u8> = full5.into_iter().flatten().collect();
    assert_eq!(reconstructed, client_hello);

    // 3. Full10
    let full10 = fragment_packet(&client_hello, FragmentStrategy::Full10, &settings);
    assert_eq!(full10[0].len(), 10);
    let reconstructed10: Vec<u8> = full10.into_iter().flatten().collect();
    assert_eq!(reconstructed10, client_hello);

    // 4. Full20
    let full20 = fragment_packet(&client_hello, FragmentStrategy::Full20, &settings);
    assert_eq!(full20[0].len(), 20);
    let reconstructed20: Vec<u8> = full20.into_iter().flatten().collect();
    assert_eq!(reconstructed20, client_hello);

    // 5. Half
    let half = fragment_packet(&client_hello, FragmentStrategy::Half, &settings);
    assert_eq!(half.len(), 2);
    let reconstructed_half: Vec<u8> = half.into_iter().flatten().collect();
    assert_eq!(reconstructed_half, client_hello);

    // 6. SniBoundary
    let sni_boundary = fragment_packet(&client_hello, FragmentStrategy::SniBoundary, &settings);
    assert_eq!(sni_boundary.len(), 2);
    let (sni_offset, _) = locate_sni(&client_hello).unwrap();
    assert_eq!(sni_boundary[0].len(), sni_offset);
    let reconstructed_boundary: Vec<u8> = sni_boundary.into_iter().flatten().collect();
    assert_eq!(reconstructed_boundary, client_hello);

    // 7. SniSplit
    let sni_split = fragment_packet(&client_hello, FragmentStrategy::SniSplit, &settings);
    assert_eq!(sni_split.len(), 2);
    let reconstructed_split: Vec<u8> = sni_split.into_iter().flatten().collect();
    assert_eq!(reconstructed_split, client_hello);

    // 8. TlsRecordFrag
    let tls_frag = fragment_packet(&client_hello, FragmentStrategy::TlsRecordFrag, &settings);
    assert_eq!(tls_frag.len(), 2);
    assert_eq!(tls_frag[0][0], 0x16);
    assert_eq!(tls_frag[1][0], 0x16);

    // 9. TlsSniRecords
    let tls_sni_records = fragment_packet(&client_hello, FragmentStrategy::TlsSniRecords, &settings);
    assert_eq!(tls_sni_records.len(), 2);
    assert_eq!(tls_sni_records[0][0], 0x16);
    assert_eq!(tls_sni_records[1][0], 0x16);

    // 10. FinalMaskTlsHello
    let final_mask = fragment_packet(&client_hello, FragmentStrategy::FinalMaskTlsHello, &settings);
    assert!(!final_mask.is_empty());
}

#[test]
fn test_final_mask_rewriting() {
    let client_hello = build_test_client_hello("ignitelimit.com");
    let settings = FinalMaskSettings {
        packet: "tlshello".to_string(),
        length: 5,
        delay_ms: 0,
        max_split: 2,
    };

    let rewrite = rewrite_final_mask_writes(&client_hello, &settings);
    assert!(rewrite.first_write.len() > 10);
    assert_eq!(rewrite.first_write[0], 0x16); // First TLS record
    assert_eq!(((rewrite.first_write[3] as usize) << 8) | (rewrite.first_write[4] as usize), 5); // 5 bytes payload in record 1

    let contiguous = rewrite_final_mask_tls_hello(&client_hello, &settings);
    assert_eq!(contiguous, rewrite.first_write);
}

#[test]
fn test_carrier_route_selector_cooldown() {
    let edge1 = CarrierEdgeProfile::new("104.18.1.1", 443, "primary", 2);
    let edge2 = CarrierEdgeProfile::new("104.18.1.2", 443, "irancell", 100);
    let edge3 = CarrierEdgeProfile::new("172.66.0.1", 443, "fallback", 2);

    let edges = vec![edge1.clone(), edge2.clone(), edge3.clone()];
    let mut selector = CarrierRouteSelector::new(Duration::from_millis(100));

    // Initially all are healthy
    let ordered = selector.ordered_edges(&edges);
    assert_eq!(ordered, edges);

    // Mark edge1 as failed
    selector.record_failure(&edge1);
    assert!(selector.is_in_cooldown(&edge1));

    // Ordered list should place edge1 at the end
    let ordered_after_fail = selector.ordered_edges(&edges);
    assert_eq!(ordered_after_fail[0], edge2);
    assert_eq!(ordered_after_fail[1], edge3);
    assert_eq!(ordered_after_fail[2], edge1);

    // Record success on edge1 clears cooldown immediately
    selector.record_success(&edge1);
    assert!(!selector.is_in_cooldown(&edge1));
    let ordered_after_success = selector.ordered_edges(&edges);
    assert_eq!(ordered_after_success[0], edge1);
}
