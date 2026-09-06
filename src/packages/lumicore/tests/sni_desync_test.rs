use lumicore::evasion::sni_desync::{compute_out_of_window_seq, SniDesyncPlanner};
use lumicore::evasion::tls_fragmenter::TlsFragmentStrategy;

#[test]
fn test_sni_desync_seq_calculation() {
    // ISN = 1000, fake_len = 500
    // seq = (1000 + 1 - 500) & 0xFFFFFFFF = 501
    let seq = compute_out_of_window_seq(1000, 500);
    assert_eq!(seq, 501);

    // Sequence wrap-around below zero
    // ISN = 10, fake_len = 50
    // (10 + 1 - 50) = -39
    let wrapped = compute_out_of_window_seq(10, 50);
    assert_eq!(wrapped, (10i64 + 1 - 50i64) as u32);
}

#[test]
fn test_sni_desync_plan_generation() {
    let real_hello = vec![0x16, 0x03, 0x01, 0x00, 0x50, 0x01, 0x02, 0x03, 0x04];
    let fake_hello = vec![0x16, 0x03, 0x01, 0x00, 0x20, 0xDE, 0xAD, 0xBE, 0xEF];
    let client_isn = 0x12345678;

    let segments = SniDesyncPlanner::plan(
        client_isn,
        &real_hello,
        &fake_hello,
        TlsFragmentStrategy::FixedChunks(4),
        5,
    );

    // Must contain 1 fake packet + fragmented real packets
    assert!(segments.len() >= 2);

    // First packet must be decoy with out-of-window sequence number
    let first = &segments[0];
    assert!(first.is_decoy);
    assert_eq!(first.seq_num, compute_out_of_window_seq(client_isn, fake_hello.len()));
    assert_eq!(first.payload, fake_hello);

    // Subsequent packets must be real fragments starting at client_isn + 1
    assert!(!segments[1].is_decoy);
    assert_eq!(segments[1].seq_num, client_isn + 1);

    // Total payload of real fragments must equal real_hello
    let reconstructed: Vec<u8> = segments[1..]
        .iter()
        .flat_map(|s| s.payload.clone())
        .collect();
    assert_eq!(reconstructed, real_hello);
}
