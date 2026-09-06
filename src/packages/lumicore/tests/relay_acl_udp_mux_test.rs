use lumicore::relay::{RelayAclFilter, RelayAclVerdict, UdpOverTcpFrame, UdpMuxError};
use std::net::IpAddr;

#[test]
fn test_relay_acl_source_whitelist_ipv4_and_ipv6() {
    let filter = RelayAclFilter::new_default();

    // Permitted Cloudflare edge ingress addresses
    let cf_ip1: IpAddr = "104.16.24.5".parse().unwrap();
    let cf_ip2: IpAddr = "172.67.182.11".parse().unwrap();
    let cf_ip3: IpAddr = "162.158.5.10".parse().unwrap();
    let cf_ip4: IpAddr = "198.41.130.1".parse().unwrap();
    let cf_v6: IpAddr = "2606:4700:3033::6815:1805".parse().unwrap();

    assert!(filter.is_source_allowed(&cf_ip1));
    assert!(filter.is_source_allowed(&cf_ip2));
    assert!(filter.is_source_allowed(&cf_ip3));
    assert!(filter.is_source_allowed(&cf_ip4));
    assert!(filter.is_source_allowed(&cf_v6));

    // Non-permitted sources (ISP direct, arbitrary public, private LAN)
    let non_cf1: IpAddr = "8.8.8.8".parse().unwrap();
    let non_cf2: IpAddr = "185.199.108.153".parse().unwrap();
    let non_cf3: IpAddr = "192.168.1.100".parse().unwrap();
    let non_cf_v6: IpAddr = "2001:4860:4860::8888".parse().unwrap();

    assert!(!filter.is_source_allowed(&non_cf1));
    assert!(!filter.is_source_allowed(&non_cf2));
    assert!(!filter.is_source_allowed(&non_cf3));
    assert!(!filter.is_source_allowed(&non_cf_v6));
}

#[test]
fn test_relay_acl_destination_blacklist_trackers() {
    let filter = RelayAclFilter::new_default();

    // Blocked destinations: loopback and torrent trackers
    let loopback_v4: IpAddr = "127.0.0.1".parse().unwrap();
    let loopback_v6: IpAddr = "::1".parse().unwrap();
    let tracker1: IpAddr = "93.158.213.92".parse().unwrap();
    let tracker2: IpAddr = "208.83.20.20".parse().unwrap();
    let tracker3: IpAddr = "185.102.219.163".parse().unwrap();

    assert!(!filter.is_destination_allowed(&loopback_v4));
    assert!(!filter.is_destination_allowed(&loopback_v6));
    assert!(!filter.is_destination_allowed(&tracker1));
    assert!(!filter.is_destination_allowed(&tracker2));
    assert!(!filter.is_destination_allowed(&tracker3));

    // Permitted clean destinations
    let clean1: IpAddr = "1.1.1.1".parse().unwrap();
    let clean2: IpAddr = "142.250.190.46".parse().unwrap();
    let clean3: IpAddr = "2606:4700:4700::1111".parse().unwrap();

    assert!(filter.is_destination_allowed(&clean1));
    assert!(filter.is_destination_allowed(&clean2));
    assert!(filter.is_destination_allowed(&clean3));
}

#[test]
fn test_relay_acl_evaluate_verdicts() {
    let filter = RelayAclFilter::new_default();

    let allowed_src: IpAddr = "104.16.20.1".parse().unwrap();
    let blocked_src: IpAddr = "8.8.8.8".parse().unwrap();
    let allowed_dst: IpAddr = "1.1.1.1".parse().unwrap();
    let blocked_dst: IpAddr = "127.0.0.1".parse().unwrap();

    assert_eq!(filter.evaluate(&allowed_src, &allowed_dst), RelayAclVerdict::Allowed);
    assert_eq!(filter.evaluate(&blocked_src, &allowed_dst), RelayAclVerdict::SourceNotAllowed(blocked_src));
    assert_eq!(filter.evaluate(&allowed_src, &blocked_dst), RelayAclVerdict::DestinationBlocked(blocked_dst));
}

#[test]
fn test_udp_over_tcp_frame_roundtrip() {
    let session_id = [0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33];
    let stream_tag = [0x55, 0x66];
    let payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"; // DNS query

    let frame = UdpOverTcpFrame::new(session_id, stream_tag, payload.to_vec());
    let encoded = frame.encode();
    assert_eq!(encoded.len(), 8 + payload.len());

    let decoded = UdpOverTcpFrame::decode(&encoded).expect("frame decoding should succeed");
    assert_eq!(decoded.session_id, session_id);
    assert_eq!(decoded.stream_tag, stream_tag);
    assert_eq!(decoded.payload, payload);

    // Response building and decoding
    let dns_reply = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00";
    let resp_bytes = UdpOverTcpFrame::build_response(stream_tag, dns_reply);
    assert_eq!(resp_bytes.len(), 2 + dns_reply.len());

    let (resp_tag, resp_payload) = UdpOverTcpFrame::decode_response(&resp_bytes).expect("response decode should succeed");
    assert_eq!(resp_tag, stream_tag);
    assert_eq!(resp_payload, dns_reply);

    // Truncated buffer check
    let short = [0x01, 0x02, 0x03];
    assert_eq!(UdpOverTcpFrame::decode(&short), Err(UdpMuxError::BufferTooShort));
    assert_eq!(UdpOverTcpFrame::decode_response(&short[..1]), Err(UdpMuxError::BufferTooShort));

    // Channel key
    let key = UdpOverTcpFrame::channel_key("1.1.1.1:53", &session_id, &stream_tag);
    assert_eq!(key, "1.1.1.1:53:aabbcc1122335566");
}
