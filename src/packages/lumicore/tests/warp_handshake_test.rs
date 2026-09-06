use lumicore::scanner::warp_handshake::{
    build_initiation_packet, build_probe_packet, generate_noise_bursts, select_random_warp_port,
    validate_handshake_response, WarpHandshakeError, DEFAULT_WARP_PEER_PUBLIC_KEY,
    INITIATION_PACKET_LEN, RESPONSE_PACKET_LEN, WARP_IPV4_PREFIXES, WARP_PORTS,
    WG_MSG_INITIATION, WG_MSG_RESPONSE,
};

#[test]
fn test_warp_prober_constants() {
    assert_eq!(WARP_PORTS.len(), 54);
    assert_eq!(WARP_IPV4_PREFIXES.len(), 6);
    assert_eq!(DEFAULT_WARP_PEER_PUBLIC_KEY, "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=");

    let port = select_random_warp_port();
    assert!(WARP_PORTS.contains(&port));

    let bursts = generate_noise_bursts(2, 10, 50);
    assert_eq!(bursts.len(), 2);
}

#[test]
fn test_warp_probe_packet_generation() {
    let packet = build_probe_packet(42);
    assert_eq!(packet.len(), INITIATION_PACKET_LEN);

    let msg_type = u32::from_le_bytes(packet[0..4].try_into().unwrap());
    assert_eq!(msg_type, WG_MSG_INITIATION);

    let sender_index = u32::from_le_bytes(packet[4..8].try_into().unwrap());
    assert_eq!(sender_index, 42);
}

#[test]
fn test_warp_response_validation_roundtrip() {
    let mut resp = [0u8; RESPONSE_PACKET_LEN];
    // Msg type 2
    resp[0..4].copy_from_slice(&WG_MSG_RESPONSE.to_le_bytes());
    // Peer index
    resp[4..8].copy_from_slice(&777u32.to_le_bytes());
    // Our receiver index
    resp[8..12].copy_from_slice(&42u32.to_le_bytes());
    // Ephemeral
    resp[12..60].fill(0x11);
    // Mac1
    resp[60..76].fill(0x22);

    let info = validate_handshake_response(&resp, 42).expect("valid response");
    assert_eq!(info.peer_index, 777);
    assert_eq!(info.our_index, 42);
    assert_eq!(info.encrypted_ephemeral[0], 0x11);
    assert_eq!(info.mac1[0], 0x22);
}

#[test]
fn test_build_initiation_packet_direct() {
    let ephem = [0x11; 32];
    let enc_static = [0x22; 48];
    let enc_time = [0x33; 28];
    let mac1 = [0x44; 16];
    let packet = build_initiation_packet(10, &ephem, &enc_static, &enc_time, &mac1);
    assert_eq!(packet.len(), INITIATION_PACKET_LEN);
    assert_eq!(&packet[0..4], &[1, 0, 0, 0]);
    assert_eq!(&packet[4..8], &[10, 0, 0, 0]);
}

#[test]
fn test_warp_response_validation_errors() {
    let short = vec![0u8; 50];
    assert!(matches!(
        validate_handshake_response(&short, 42),
        Err(WarpHandshakeError::PacketTooShort { .. })
    ));

    let mut bad_type = vec![0u8; 92];
    bad_type[0..4].copy_from_slice(&1u32.to_le_bytes()); // Wrong message type
    assert!(matches!(
        validate_handshake_response(&bad_type, 42),
        Err(WarpHandshakeError::InvalidMessageType { .. })
    ));

    let mut bad_index = vec![0u8; 92];
    bad_index[0..4].copy_from_slice(&2u32.to_le_bytes());
    bad_index[8..12].copy_from_slice(&99u32.to_le_bytes()); // Index mismatch
    assert!(matches!(
        validate_handshake_response(&bad_index, 42),
        Err(WarpHandshakeError::SenderIndexMismatch { expected: 42, found: 99 })
    ));
}
