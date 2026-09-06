use lumicore::transport::covert_dead_drop::{
    decode_sid_b32, encode_sid_b32, CovertCryptoSession, CovertDeadDropFilename,
    CovertWireFrame, Direction, FilenameKind, FrameKind,
    ReplayWindow, HEADER_LEN,
};

#[test]
fn test_base32_sid_roundtrip() {
    let sid = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    ];
    let encoded = encode_sid_b32(&sid);
    assert_eq!(encoded.len(), 26);
    let decoded = decode_sid_b32(&encoded).expect("valid base32");
    assert_eq!(decoded, sid);
}

#[test]
fn test_storage_filenames() {
    let sid = [0x55; 16];

    let hello = CovertDeadDropFilename {
        kind: FilenameKind::Hello,
        sid,
        seq: 0,
    };
    let formatted = hello.format();
    assert!(formatted.starts_with("h_"));
    assert_eq!(CovertDeadDropFilename::parse(&formatted), Some(hello));

    let frame_c2r = CovertDeadDropFilename {
        kind: FilenameKind::Frame(Direction::ClientToRelay),
        sid,
        seq: 100,
    };
    let formatted_c2r = frame_c2r.format();
    assert!(formatted_c2r.starts_with("c2r_"));
    assert_eq!(CovertDeadDropFilename::parse(&formatted_c2r), Some(frame_c2r));

    let frame_r2c = CovertDeadDropFilename {
        kind: FilenameKind::Frame(Direction::RelayToClient),
        sid,
        seq: 200,
    };
    let formatted_r2c = frame_r2c.format();
    assert!(formatted_r2c.starts_with("r2c_"));
    assert_eq!(CovertDeadDropFilename::parse(&formatted_r2c), Some(frame_r2c));
}

#[test]
fn test_wire_frame_lifecycle() {
    let sid = [0xAA; 16];
    let payload = b"encrypted covert stream data".to_vec();
    let frame = CovertWireFrame::new(FrameKind::Data, sid, 55, payload.clone());

    let encoded = frame.encode();
    assert_eq!(encoded.len(), HEADER_LEN + payload.len());

    let decoded = CovertWireFrame::decode(&encoded).expect("decode ok");
    assert_eq!(decoded, frame);
}

#[test]
fn test_replay_window_behavior() {
    let mut window = ReplayWindow::new();
    assert!(window.check_and_update(10));
    assert!(window.check_and_update(11));
    assert!(window.check_and_update(15));

    // Replays must fail
    assert!(!window.check_and_update(10));
    assert!(!window.check_and_update(11));
    assert!(!window.check_and_update(15));

    // Unseen earlier sequences within 64-frame range must succeed
    assert!(window.check_and_update(12));
    assert!(window.check_and_update(13));
    assert!(window.check_and_update(14));

    // And then fail on replay
    assert!(!window.check_and_update(12));
}

#[test]
fn test_crypto_session_aead_full_cycle() {
    let secret = [0x99; 32];
    let sid = [0x88; 16];
    let salt = [0x77; 16];

    let session = CovertCryptoSession::new(&secret, &sid, &salt);
    let frame = CovertWireFrame::new(
        FrameKind::Data,
        sid,
        1,
        b"highly sensitive transmission".to_vec(),
    );

    let sealed = session
        .seal(&frame, Direction::ClientToRelay)
        .expect("seal ok");

    let opened = session
        .open(&sealed, &sid, 1, Direction::ClientToRelay)
        .expect("open ok");

    assert_eq!(opened, frame);
}
