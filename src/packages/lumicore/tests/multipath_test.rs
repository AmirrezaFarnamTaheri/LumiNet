use std::time::Duration;
use lumicore::multipath::{
    AdaptiveConfig, AdaptiveController, ControllerTransition, DedupBuffer, MpFrame,
    MpFrameType, MP_HEADER_LEN,
};

#[test]
fn test_mpframe_all_types() {
    let sid = [0x44; 16];
    let types = [
        MpFrameType::Hello,
        MpFrameType::HelloAck,
        MpFrameType::Data,
        MpFrameType::Close,
        MpFrameType::Ping,
        MpFrameType::Pong,
    ];

    for ft in types {
        let frame = MpFrame::new(ft, sid, 100, b"multipath test payload".to_vec());
        let encoded = frame.encode();
        assert_eq!(encoded.len(), MP_HEADER_LEN + frame.payload.len());
        let decoded = MpFrame::decode(&encoded).expect("decode ok");
        assert_eq!(decoded, frame);
    }
}

#[test]
fn test_dedup_buffer_complex_reordering() {
    let mut buf = DedupBuffer::new(50);

    // Frame arrivals: 3, 1, 4, 0, 2
    assert!(buf.push(3, b"frame 3".to_vec()).unwrap().is_empty());
    assert!(buf.push(1, b"frame 1".to_vec()).unwrap().is_empty());
    assert!(buf.push(4, b"frame 4".to_vec()).unwrap().is_empty());

    // Frame 0 arrives -> delivers frame 0 and frame 1!
    let del1 = buf.push(0, b"frame 0".to_vec()).unwrap();
    assert_eq!(del1.len(), 2);
    assert_eq!(del1[0], b"frame 0".to_vec());
    assert_eq!(del1[1], b"frame 1".to_vec());
    assert_eq!(buf.next_seq(), 2);

    // Frame 2 arrives -> delivers frame 2, 3, 4!
    let del2 = buf.push(2, b"frame 2".to_vec()).unwrap();
    assert_eq!(del2.len(), 3);
    assert_eq!(del2[0], b"frame 2".to_vec());
    assert_eq!(del2[1], b"frame 3".to_vec());
    assert_eq!(del2[2], b"frame 4".to_vec());
    assert_eq!(buf.next_seq(), 5);
}

#[test]
fn test_dedup_buffer_gap_timeout() {
    let mut buf = DedupBuffer::with_initial_seq(0, 10, Duration::from_millis(5));

    // Send frame 5 directly, leaving gap 0..4
    buf.push(5, b"frame 5".to_vec()).unwrap();
    assert_eq!(buf.next_seq(), 0);

    std::thread::sleep(Duration::from_millis(10));
    let recovered = buf.check_timeout();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], b"frame 5".to_vec());
    assert_eq!(buf.next_seq(), 6);
}

#[test]
fn test_adaptive_controller_lifecycle() {
    let mut ctrl = AdaptiveController::new(AdaptiveConfig {
        min_active: 1,
        max_active: 3,
        demote_threshold: 0.10,
        promote_margin: 0.20,
        min_frames: 10,
    });

    ctrl.register_path("tunnel_a");
    ctrl.register_path("tunnel_b");

    for _ in 0..15 {
        ctrl.record_win("tunnel_a");
        ctrl.record_frame("tunnel_b");
    }

    let transition = ctrl.evaluate_tick();
    assert_eq!(
        transition,
        Some(ControllerTransition::Demoted {
            path_id: "tunnel_b".to_string()
        })
    );
}
