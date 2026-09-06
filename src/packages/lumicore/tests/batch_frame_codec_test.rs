use lumicore::relay::{
    BatchCodec, DrainSnapshot, Frame, TransactionalSession, FLAG_FIN, FLAG_SYN, SESSION_ID_LEN,
};

#[test]
fn test_frame_marshal_unmarshal_roundtrip() {
    let session_id = [0xAB; SESSION_ID_LEN];
    let original = Frame::new(session_id, 42, FLAG_SYN)
        .with_target("target.server.internal:443")
        .with_payload(b"GET / HTTP/1.1\r\nHost: target\r\n\r\n".to_vec());

    let marshaled = original.marshal().expect("frame marshal should succeed");
    let (decoded, consumed) = Frame::unmarshal(&marshaled).expect("frame unmarshal should succeed");

    assert_eq!(consumed, marshaled.len());
    assert_eq!(decoded.session_id, session_id);
    assert_eq!(decoded.seq, 42);
    assert_eq!(decoded.flags, FLAG_SYN);
    assert_eq!(decoded.target, "target.server.internal:443");
    assert_eq!(decoded.payload, b"GET / HTTP/1.1\r\nHost: target\r\n\r\n");
}

#[test]
fn test_batch_codec_seal_open_roundtrip() {
    let key = [0x42u8; 32];
    let codec = BatchCodec::new(&key);

    let client_id = [0x07u8; 16];
    let f1 = Frame::new([1u8; 16], 0, FLAG_SYN)
        .with_target("example.com:80")
        .with_payload(vec![1, 2, 3, 4]);
    let f2 = Frame::new([1u8; 16], 1, 0)
        .with_payload(vec![5, 6, 7, 8, 9, 10]);
    let f3 = Frame::new([2u8; 16], 0, FLAG_SYN)
        .with_target("api.google.com:443");

    let frames = vec![f1, f2, f3];
    let encoded_b64 = codec
        .encode_batch(&client_id, &frames)
        .expect("batch encoding should succeed");

    assert!(!encoded_b64.is_empty());

    let (decoded_client_id, decoded_frames) = codec
        .decode_batch(&encoded_b64)
        .expect("batch decoding should succeed");

    assert_eq!(decoded_client_id, client_id);
    assert_eq!(decoded_frames.len(), 3);
    assert_eq!(decoded_frames[0].target, "example.com:80");
    assert_eq!(decoded_frames[0].payload, vec![1, 2, 3, 4]);
    assert_eq!(decoded_frames[1].payload, vec![5, 6, 7, 8, 9, 10]);
    assert_eq!(decoded_frames[2].target, "api.google.com:443");
}

#[test]
fn test_batch_codec_tampered_payload_rejected() {
    let key = [0x99u8; 32];
    let codec = BatchCodec::new(&key);
    let client_id = [0x01u8; 16];
    let frames = vec![Frame::new([1u8; 16], 0, FLAG_SYN).with_target("secure.corp")];

    let encoded_b64 = codec.encode_batch(&client_id, &frames).unwrap();
    // Tamper with one base64 character in the middle
    let mut chars: Vec<char> = encoded_b64.chars().collect();
    let mid = chars.len() / 2;
    chars[mid] = if chars[mid] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();

    let result = codec.decode_batch(&tampered);
    assert!(result.is_err(), "tampered ciphertext must fail authentication tag check");
}

#[test]
fn test_transactional_session_drain_and_rollback() {
    let session_id = [0x55u8; 16];
    let mut session = TransactionalSession::new(session_id, "upstream.corp:8443", true);

    // Initial connect data ride-along
    session.enqueue_initial_data(b"CLIENT_HELLO_DATA");
    session.enqueue_tx(b"_MORE_STREAM_DATA");

    // Drain with max payload 10 bytes and max 2 frames
    let (frames, snap) = session.drain_tx_limited_txn(10, 2);
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].flags & FLAG_SYN, FLAG_SYN);
    assert_eq!(frames[0].target, "upstream.corp:8443");
    assert_eq!(frames[0].payload, b"CLIENT_HEL"); // first 10 bytes
    assert_eq!(frames[1].payload, b"LO_DATA_MO"); // next 10 bytes

    let snapshot = snap.expect("snapshot must be captured on non-empty drain");

    // Simulate new data enqueued while batch was in-flight
    session.enqueue_tx(b"_NEW_DATA_DURING_FLIGHT");

    // Simulate batch transport failure -> trigger rollback!
    session.rollback_drain(snapshot);

    // After rollback, the drained data must be restored in front of the newly arrived data!
    let (restored_frames, _) = session.drain_tx_limited_txn(100, 10);
    assert_eq!(restored_frames.len(), 1);
    assert_eq!(restored_frames[0].flags & FLAG_SYN, FLAG_SYN);
    assert_eq!(restored_frames[0].target, "upstream.corp:8443");
    assert_eq!(
        restored_frames[0].payload,
        b"CLIENT_HELLO_DATA_MORE_STREAM_DATA_NEW_DATA_DURING_FLIGHT"
    );
}

#[test]
fn test_transactional_session_out_of_order_rx_reassembly() {
    let session_id = [0x77u8; 16];
    let mut session = TransactionalSession::new(session_id, "downstream.target", false);

    // Frame 1 arrives before Frame 0
    let f1 = Frame::new(session_id, 1, 0).with_payload(b"WORLD".to_vec());
    let delivered1 = session.process_rx(f1);
    assert!(delivered1.is_empty(), "out-of-order frame 1 must be buffered");

    // Frame 2 with FIN arrives
    let f2 = Frame::new(session_id, 2, FLAG_FIN);
    let delivered2 = session.process_rx(f2);
    assert!(delivered2.is_empty(), "out-of-order frame 2 must be buffered");

    // Frame 0 arrives
    let f0 = Frame::new(session_id, 0, 0).with_payload(b"HELLO ".to_vec());
    let delivered0 = session.process_rx(f0);

    // Should now deliver f0 and f1 in order, and detect FIN
    assert_eq!(delivered0.len(), 2);
    assert_eq!(delivered0[0], b"HELLO ");
    assert_eq!(delivered0[1], b"WORLD");
    assert!(session.rx_closed, "FIN must close rx");
}
