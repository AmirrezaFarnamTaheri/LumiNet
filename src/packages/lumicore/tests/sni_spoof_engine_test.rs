//! Unit tests for SNI spoof engine and DPI desync coordinator.

use lumicore::evasion::sni_spoof_engine::*;
use std::net::Ipv4Addr;

#[test]
fn test_4tuple_key_reversal() {
    let src = Ipv4Addr::new(192, 168, 1, 100);
    let dst = Ipv4Addr::new(104, 21, 5, 5);
    let key = Conn4TupleKey::new(src, 54321, dst, 443);

    assert_eq!(key.src_port, 54321);
    assert_eq!(key.dst_port, 443);

    let rev = key.reverse();
    assert_eq!(rev.src_ip, key.dst_ip);
    assert_eq!(rev.dst_ip, key.src_ip);
    assert_eq!(rev.src_port, 443);
    assert_eq!(rev.dst_port, 54321);
}

#[test]
fn test_tls_clienthello_template_synthesis() {
    let fake_sni = "speedtest.net";
    let random = [0x11u8; 32];
    let session_id = [0x22u8; 32];
    let key_share = [0x33u8; 32];

    let packet = TlsClientHelloTemplate::build(fake_sni, random, session_id, key_share);
    // Canonical length must strictly equal 517 bytes
    assert_eq!(packet.len(), 517);

    // Verify TLS record header
    assert_eq!(packet[0], 0x16); // Handshake
    assert_eq!(packet[1], 0x03); // TLS 1.0 record version
    assert_eq!(packet[2], 0x01);

    // Verify embedded random entropy
    assert_eq!(&packet[11..43], &random);
    // Verify embedded session_id
    assert_eq!(&packet[44..76], &session_id);

    // Test with another SNI of different length (e.g. 6 chars "mci.ir")
    let packet2 = TlsClientHelloTemplate::build("mci.ir", random, session_id, key_share);
    assert_eq!(packet2.len(), 517);
}

#[test]
fn test_iptcp_packet_helpers_and_fake_payload() {
    // Construct a synthetic 40-byte IPv4 + TCP ACK packet
    let mut raw_packet = vec![0u8; 40];
    // IPv4 Header (20 bytes)
    raw_packet[0] = 0x45; // Version 4, IHL 5 (20 bytes)
    raw_packet[1] = 0x00; // DSCP/ECN
    raw_packet[2] = 0x00; // Total Length (40 bytes)
    raw_packet[3] = 0x28;
    raw_packet[4] = 0x12; // Identification = 0x1234
    raw_packet[5] = 0x34;
    raw_packet[6] = 0x40; // Flags (Don't Fragment)
    raw_packet[7] = 0x00;
    raw_packet[8] = 64;   // TTL
    raw_packet[9] = 6;    // Protocol: TCP
    raw_packet[12..16].copy_from_slice(&[192, 168, 1, 10]); // Src IP
    raw_packet[16..20].copy_from_slice(&[104, 21, 5, 5]);   // Dst IP
    IpTcpPacket::compute_ip_checksum(&mut raw_packet[..20]);

    // TCP Header (20 bytes)
    raw_packet[20] = 0xD4; // Src Port: 54321 (0xD431)
    raw_packet[21] = 0x31;
    raw_packet[22] = 0x01; // Dst Port: 443 (0x01BB)
    raw_packet[23] = 0xBB;
    raw_packet[24..28].copy_from_slice(&100_000u32.to_be_bytes()); // Seq = 100,000
    raw_packet[28..32].copy_from_slice(&200_000u32.to_be_bytes()); // Ack = 200,000
    raw_packet[32] = 0x50; // Data Offset: 5 (20 bytes)
    raw_packet[33] = TCP_FLAG_ACK; // Flags: ACK
    raw_packet[34] = 0x01; // Window size: 256
    raw_packet[35] = 0x00;
    IpTcpPacket::compute_tcp_checksum(&mut raw_packet, 20, 20);

    assert!(IpTcpPacket::is_ipv4_tcp(&raw_packet));
    assert_eq!(IpTcpPacket::ip_header_len(&raw_packet), 20);
    assert_eq!(IpTcpPacket::tcp_header_len(&raw_packet, 20), 20);
    assert_eq!(IpTcpPacket::src_port(&raw_packet, 20), 54321);
    assert_eq!(IpTcpPacket::dst_port(&raw_packet, 20), 443);
    assert_eq!(IpTcpPacket::seq_num(&raw_packet, 20), 100_000);
    assert_eq!(IpTcpPacket::flags(&raw_packet, 20), TCP_FLAG_ACK);

    // Build fake payload packet
    let fake_payload = b"FAKE_TLS_CLIENT_HELLO_PAYLOAD";
    let fake_seq = 99_000u32; // (syn_seq + 1 - fake_len)
    let fake_pkt = IpTcpPacket::build_fake_payload_packet(&raw_packet, fake_payload, fake_seq)
        .expect("Build fake packet should succeed");

    assert_eq!(fake_pkt.len(), 40 + fake_payload.len());
    // Verify total length field in IPv4 header
    assert_eq!(IpTcpPacket::total_len(&fake_pkt), (40 + fake_payload.len()) as u16);
    // Verify IPv4 ID incremented from 0x1234 to 0x1235
    let new_id = u16::from_be_bytes([fake_pkt[4], fake_pkt[5]]);
    assert_eq!(new_id, 0x1235);
    // Verify TCP flags now include PSH
    assert_eq!(IpTcpPacket::flags(&fake_pkt, 20), TCP_FLAG_ACK | TCP_FLAG_PSH);
    // Verify TCP sequence overwritten
    assert_eq!(IpTcpPacket::seq_num(&fake_pkt, 20), fake_seq);
}

#[test]
fn test_cloudflare_cidr_matcher() {
    // 104.16.0.0/13
    assert!(CloudflareCidrMatcher::is_cloudflare_ip(Ipv4Addr::new(104, 16, 12, 34)));
    assert!(CloudflareCidrMatcher::is_cloudflare_ip(Ipv4Addr::new(104, 21, 88, 99)));
    // 172.64.0.0/13
    assert!(CloudflareCidrMatcher::is_cloudflare_ip(Ipv4Addr::new(172, 64, 1, 1)));
    // 162.158.0.0/15
    assert!(CloudflareCidrMatcher::is_cloudflare_ip(Ipv4Addr::new(162, 159, 10, 20)));
    // 188.114.96.0/20
    assert!(CloudflareCidrMatcher::is_cloudflare_ip(Ipv4Addr::new(188, 114, 97, 1)));

    // Non-Cloudflare public IPs
    assert!(!CloudflareCidrMatcher::is_cloudflare_ip(Ipv4Addr::new(8, 8, 8, 8)));
    assert!(!CloudflareCidrMatcher::is_cloudflare_ip(Ipv4Addr::new(142, 250, 190, 46))); // Google
    assert!(!CloudflareCidrMatcher::is_cloudflare_ip(Ipv4Addr::new(10, 0, 0, 1)));       // Private
}

#[test]
fn test_sni_domain_cleaner() {
    assert_eq!(
        SniDomainCleaner::clean_domain("https://cloudflare.com/path?q=1"),
        Some("cloudflare.com".to_string())
    );
    assert_eq!(
        SniDomainCleaner::clean_domain("   HTTP://SpeedTest.NET:443/  "),
        Some("speedtest.net".to_string())
    );
    assert_eq!(
        SniDomainCleaner::clean_domain("sub.domain.example.com:8443"),
        Some("sub.domain.example.com".to_string())
    );

    // Comment and invalid lines
    assert_eq!(SniDomainCleaner::clean_domain("# comment line"), None);
    assert_eq!(SniDomainCleaner::clean_domain("   "), None);
    assert_eq!(SniDomainCleaner::clean_domain("singleword"), None);
}

#[test]
fn test_killswitch_coordinator() {
    let mut coord = KillSwitchCoordinator::new(true);

    // Arming SNI and V2Ray
    coord.arm_sni();
    coord.arm_v2ray();

    // While both running, tick produces NoChange
    assert_eq!(coord.on_tick(true, true), KillSwitchAction::NoChange);
    assert!(!coord.is_blocked);

    // If SNI engine crashes (sni_running=false), tick produces BlockOutbound
    assert_eq!(coord.on_tick(false, true), KillSwitchAction::BlockOutbound);
    assert!(coord.is_blocked);

    // Subsequent tick while still down produces NoChange (already blocked)
    assert_eq!(coord.on_tick(false, true), KillSwitchAction::NoChange);

    // Disarm SNI and V2Ray restores unblock
    coord.disarm_sni();
    let action = coord.disarm_v2ray();
    assert_eq!(action, KillSwitchAction::UnblockOutbound);
    assert!(!coord.is_blocked);

    // Netsh rule syntax validation
    let block_cmd = KillSwitchCoordinator::netsh_block_rule("LumiNet KillSwitch");
    assert!(block_cmd.contains(&"action=block".to_string()));
    assert!(block_cmd.contains(&"name=LumiNet KillSwitch".to_string()));

    let unblock_cmd = KillSwitchCoordinator::netsh_unblock_rule("LumiNet KillSwitch");
    assert!(unblock_cmd.contains(&"delete".to_string()));
}
