//! Unit tests for SNI desync state machine & TLS template synthesizer.

use lumicore::evasion::sni_desync_state_machine::*;
use lumicore::evasion::sni_spoof::build_fake_clienthello;
use lumicore::evasion::fingerprint::BrowserFingerprint;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[test]
fn test_serverhello_synthesis_and_parsing() {
    let mut random = [0u8; 32];
    let mut session_id = [0u8; 32];
    let mut key_share = [0u8; 32];
    for i in 0..32 {
        random[i] = i as u8;
        session_id[i] = (i + 32) as u8;
        key_share[i] = (i + 64) as u8;
    }
    let app_data = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec();

    let packet = build_serverhello_with(&random, &session_id, &key_share, &app_data);
    assert!(packet.len() >= 159);

    let parsed = parse_serverhello(&packet).expect("Failed to parse ServerHello");
    assert_eq!(parsed.random, random);
    assert_eq!(parsed.session_id, session_id);
    assert_eq!(parsed.key_share, key_share);
    assert_eq!(parsed.app_data, app_data);
}

#[test]
fn test_clienthello_roundtrip_parsing() {
    let fake_sni = "auth.vercel.com";
    let fake_ch = build_fake_clienthello(fake_sni, BrowserFingerprint::Chrome);
    assert_eq!(fake_ch.len(), 517);

    let parsed = parse_clienthello(&fake_ch).expect("Failed to parse ClientHello");
    assert_eq!(parsed.sni, fake_sni);
    assert_eq!(parsed.random.len(), 32);
    assert_eq!(parsed.session_id.len(), 32);
    assert_eq!(parsed.key_share.len(), 32);
}

#[test]
fn test_tcp_handshake_state_machine_happy_path() {
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)), 54321);
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(188, 114, 98, 0)), 443);
    let mut tracker = TcpHandshakeDesyncTracker::new(local, remote);

    // 1. Outbound SYN (seq 10000, ack 0, flags SYN=0x02, payload 0)
    let act1 = tracker.handle_outbound(10000, 0, TCP_FLAG_SYN, 0, 100, 517);
    assert_eq!(act1, OutboundHandshakeAction::Pass);
    assert_eq!(tracker.phase, HandshakePhase::SynSent);

    // 2. Inbound SYN-ACK (seq 50000, ack 10001, flags SYN|ACK=0x12, payload 0)
    let act2 = tracker.handle_inbound(50000, 10001, TCP_FLAG_SYN | TCP_FLAG_ACK, 0);
    assert_eq!(act2, InboundHandshakeAction::Pass);
    assert_eq!(tracker.phase, HandshakePhase::SynAckReceived);

    // 3. Outbound ACK (seq 10001, ack 50001, flags ACK=0x10, payload 0)
    let act3 = tracker.handle_outbound(10001, 50001, TCP_FLAG_ACK, 0, 100, 517);
    match act3 {
        OutboundHandshakeAction::ScheduleDecoyInjection { decoy_seq, new_ident } => {
            // (10000 + 1) - 517 = 9484
            assert_eq!(decoy_seq, 9484);
            assert_eq!(new_ident, 101);
        }
        other => panic!("Unexpected action: {:?}", other),
    }
    assert_eq!(tracker.phase, HandshakePhase::DecoyInjected);

    // 4. Inbound ACK (seq 50001, ack 10001, flags ACK=0x10, payload 0)
    let act4 = tracker.handle_inbound(50001, 10001, TCP_FLAG_ACK, 0);
    assert_eq!(act4, InboundHandshakeAction::DecoyAckReceived);
    assert_eq!(tracker.phase, HandshakePhase::DecoyAcknowledged);
}

#[test]
fn test_tcp_handshake_error_handling() {
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)), 54321);
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(188, 114, 98, 0)), 443);
    let mut tracker = TcpHandshakeDesyncTracker::new(local, remote);

    // Outbound SYN with non-zero ack
    let act = tracker.handle_outbound(10000, 999, TCP_FLAG_SYN, 0, 100, 517);
    assert!(matches!(act, OutboundHandshakeAction::UnexpectedPacket(_)));
    assert_eq!(tracker.phase, HandshakePhase::Terminated);

    // Reset tracker
    let mut tracker2 = TcpHandshakeDesyncTracker::new(local, remote);
    tracker2.handle_outbound(10000, 0, TCP_FLAG_SYN, 0, 100, 517);

    // Inbound packet with invalid ack
    let act_in = tracker2.handle_inbound(50000, 99999, TCP_FLAG_SYN | TCP_FLAG_ACK, 0);
    assert!(matches!(act_in, InboundHandshakeAction::UnexpectedPacket(_)));
    assert_eq!(tracker2.phase, HandshakePhase::Terminated);
}

#[test]
fn test_client_response_envelope() {
    let payload = b"GET / HTTP/1.1\r\nHost: target.com\r\n\r\n";
    let envelope = build_client_response_with(payload);
    assert_eq!(envelope.len(), 11 + payload.len());

    let parsed = parse_client_response(&envelope).expect("Failed to parse client response");
    assert_eq!(parsed, payload);
}

