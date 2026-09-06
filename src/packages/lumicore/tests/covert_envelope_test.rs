use lumicore::transport::covert_envelope::{CovertEnvelope, CovertEnvelopeError, COVERT_MAGIC_BYTE};

#[test]
fn test_covert_envelope_full_lifecycle() {
    let payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
    let env = CovertEnvelope::new("session-test-uuid-42", 1001, "destination.internal:9050", payload.clone());

    let encoded = env.encode();
    assert_eq!(encoded[0], COVERT_MAGIC_BYTE);
    assert_eq!(encoded.len(), env.encoded_len());

    let (decoded, consumed) = CovertEnvelope::decode(&encoded).expect("decode failed");
    assert_eq!(consumed, encoded.len());
    assert_eq!(decoded.session_id, "session-test-uuid-42");
    assert_eq!(decoded.seq, 1001);
    assert_eq!(decoded.target_addr, "destination.internal:9050");
    assert!(!decoded.is_close);
    assert_eq!(decoded.payload, payload);
}

#[test]
fn test_covert_envelope_close_frame() {
    let env = CovertEnvelope::new_close("session-terminator", 9999);
    let encoded = env.encode();

    let (decoded, consumed) = CovertEnvelope::decode(&encoded).expect("decode close failed");
    assert_eq!(consumed, encoded.len());
    assert_eq!(decoded.session_id, "session-terminator");
    assert_eq!(decoded.seq, 9999);
    assert!(decoded.target_addr.is_empty());
    assert!(decoded.is_close);
    assert!(decoded.payload.is_empty());
}

#[test]
fn test_covert_envelope_invalid_header() {
    let bad = vec![0x00; 20];
    let err = CovertEnvelope::decode(&bad).unwrap_err();
    assert!(matches!(err, CovertEnvelopeError::InvalidMagicByte { .. }));
}

#[test]
fn test_covert_packet_reassembler_pipeline() {
    use lumicore::transport::covert_envelope::CovertPacketReassembler;

    let mut reassembler = CovertPacketReassembler::with_start_seq(100);

    // Create 3 envelopes out-of-order: seq 101, 102, 100
    let env101 = CovertEnvelope::new("sess-1", 101, "addr:80", b"World ".to_vec());
    let env102 = CovertEnvelope::new("sess-1", 102, "addr:80", b"Foo".to_vec());
    let env100 = CovertEnvelope::new("sess-1", 100, "addr:80", b"Hello ".to_vec());

    // Ingest 101: should buffer, expected_seq is 100
    let chunks = reassembler.push(env101);
    assert!(chunks.is_empty());
    assert_eq!(reassembler.buffered_count(), 1);

    // Ingest 102: should buffer
    let chunks = reassembler.push(env102);
    assert!(chunks.is_empty());
    assert_eq!(reassembler.buffered_count(), 2);

    // Ingest 100: fills gap, should pop 100, 101, 102
    let chunks = reassembler.push(env100);
    assert_eq!(chunks, b"Hello World Foo");
    assert_eq!(reassembler.buffered_count(), 0);
    assert_eq!(reassembler.expected_seq(), 103);
    assert!(!reassembler.is_closed());

    // Ingest close frame
    let close_env = CovertEnvelope::new_close("sess-1", 103);
    let chunks = reassembler.push(close_env);
    assert!(chunks.is_empty());
    assert!(reassembler.is_closed());
}

