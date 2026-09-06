use lumicore::evasion::adaptive_strategy_racer::{
    build_disposable_fake_probe, fragment_extended, locate_sni_range,
    validate_strategy_response, AdaptiveStrategyRacer, CarrierMode, ExtendedFragmentStrategy,
    StrategyResponseStatus,
};

fn build_test_client_hello(sni_host: &str) -> Vec<u8> {
    let host_bytes = sni_host.as_bytes();
    let mut pkt = Vec::new();

    pkt.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x00]);

    let handshake_start = pkt.len();
    pkt.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&[0x03, 0x03]);
    pkt.extend_from_slice(&[0x33; 32]);
    pkt.push(0x00);
    pkt.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]);
    pkt.extend_from_slice(&[0x01, 0x00]);

    let ext_len_pos = pkt.len();
    pkt.extend_from_slice(&[0x00, 0x00]);

    let ext_start = pkt.len();
    let sni_ext_len = 2 + 1 + 2 + host_bytes.len();
    pkt.extend_from_slice(&[
        0x00, 0x00,
        ((sni_ext_len >> 8) & 0xff) as u8,
        (sni_ext_len & 0xff) as u8,
    ]);

    let list_len = 1 + 2 + host_bytes.len();
    pkt.extend_from_slice(&[
        ((list_len >> 8) & 0xff) as u8,
        (list_len & 0xff) as u8,
        0x00,
        ((host_bytes.len() >> 8) & 0xff) as u8,
        (host_bytes.len() & 0xff) as u8,
    ]);
    pkt.extend_from_slice(host_bytes);

    let ext_len = pkt.len() - ext_start;
    pkt[ext_len_pos] = ((ext_len >> 8) & 0xff) as u8;
    pkt[ext_len_pos + 1] = (ext_len & 0xff) as u8;

    let hs_len = pkt.len() - handshake_start - 4;
    pkt[handshake_start + 1] = ((hs_len >> 16) & 0xff) as u8;
    pkt[handshake_start + 2] = ((hs_len >> 8) & 0xff) as u8;
    pkt[handshake_start + 3] = (hs_len & 0xff) as u8;

    let rec_len = pkt.len() - 5;
    pkt[3] = ((rec_len >> 8) & 0xff) as u8;
    pkt[4] = (rec_len & 0xff) as u8;

    pkt
}

#[test]
fn test_sni_chars_fragmentation() {
    let client_hello = build_test_client_hello("mci.ir");
    let (sni_offset, sni_len) = locate_sni_range(&client_hello).expect("Must locate SNI");
    assert_eq!(sni_len, 6); // "mci.ir" has 6 chars

    let fragments = fragment_extended(&client_hello, ExtendedFragmentStrategy::SniChars, 0);
    // prefix (start) + 6 single-char slices (no trailing extensions in this test pkt) = 7 slices total
    assert_eq!(fragments.len(), 7);
    assert_eq!(fragments[0].len(), sni_offset);
    for i in 1..=6 {
        assert_eq!(fragments[i].len(), 1);
    }

    let reconstructed: Vec<u8> = fragments.into_iter().flatten().collect();
    assert_eq!(reconstructed, client_hello);
}

#[test]
fn test_multi64_fragmentation() {
    let client_hello = build_test_client_hello("speedtest.net");
    let fragments = fragment_extended(&client_hello, ExtendedFragmentStrategy::Multi64, 64);
    assert!(fragments.len() > 1);
    assert_eq!(fragments[0].len(), 64);

    let reconstructed: Vec<u8> = fragments.into_iter().flatten().collect();
    assert_eq!(reconstructed, client_hello);
}

#[test]
fn test_response_validation() {
    // Empty
    assert_eq!(validate_strategy_response(&[]), StrategyResponseStatus::EmptyResponse);

    // TLS Alert (0x15)
    let alert = vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
    assert_eq!(validate_strategy_response(&alert), StrategyResponseStatus::AlertRejected);

    // Truncated Handshake (< 8 bytes)
    let truncated = vec![0x16, 0x03, 0x03, 0x00];
    assert_eq!(validate_strategy_response(&truncated), StrategyResponseStatus::TruncatedMalformed);

    // Valid ServerHello (length >= 8)
    let valid = vec![0x16, 0x03, 0x03, 0x00, 0x50, 0x02, 0x00, 0x00, 0x4c];
    assert_eq!(validate_strategy_response(&valid), StrategyResponseStatus::Valid);
}

#[test]
fn test_disposable_fake_probe() {
    let probe = build_disposable_fake_probe("speedtest.net");
    assert!(probe.len() > 50);
    assert_eq!(probe[0], 0x16); // Handshake
    assert_eq!(probe[5], 0x01); // ClientHello

    let loc = locate_sni_range(&probe);
    assert!(loc.is_some());
    let (offset, len) = loc.unwrap();
    assert_eq!(&probe[offset..offset + len], b"speedtest.net");
}

#[test]
fn test_adaptive_strategy_racer_ordering() {
    let mut racer = AdaptiveStrategyRacer::new(CarrierMode::Mci, "speedtest.net");
    let plan = racer.plan_strategies("104.18.8.83");
    assert!(!plan.is_empty());
    assert_eq!(plan[0].0, ExtendedFragmentStrategy::Full20);

    // Set preference for SniChars
    racer.record_success("104.18.8.83", ExtendedFragmentStrategy::SniChars);
    assert_eq!(racer.preferred_strategy("104.18.8.83"), Some(ExtendedFragmentStrategy::SniChars));

    let updated_plan = racer.plan_strategies("104.18.8.83");
    assert_eq!(updated_plan[0].0, ExtendedFragmentStrategy::SniChars);
}
