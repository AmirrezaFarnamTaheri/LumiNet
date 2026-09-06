//! Unit and integration tests for Android TUN bridge, FakeDNS mapping, and SOCKS5 address rewriter.

use lumicore::system::tun_bridge::*;
use std::net::Ipv4Addr;

#[test]
fn test_dup_fd_error_handling() {
    assert_eq!(dup_fd(-1), Err(TunBridgeError::InvalidFd(-1)));
    assert_eq!(dup_fd(-42), Err(TunBridgeError::InvalidFd(-42)));

    // On Windows or Unix, positive test fd succeeds
    assert!(dup_fd(100).is_ok());
}

#[test]
fn test_fakedns_mapper_bidirectional_lookup() {
    let mapper = FakeDnsMapper::new();
    assert_eq!(mapper.mapping_count(), 0);

    let ip1 = mapper.get_fake_ip("google.com");
    assert_eq!(ip1.octets()[0], 198);
    assert_eq!(ip1.octets()[1], 18);
    assert_eq!(mapper.mapping_count(), 1);

    // Repeated call for same host returns exact same IP
    let ip1_repeat = mapper.get_fake_ip("google.com");
    assert_eq!(ip1, ip1_repeat);

    // Case-insensitivity
    let ip1_upper = mapper.get_fake_ip("GOOGLE.COM");
    assert_eq!(ip1, ip1_upper);

    // Second host gets distinct IP
    let ip2 = mapper.get_fake_ip("cloudflare.com");
    assert_ne!(ip1, ip2);
    assert_eq!(mapper.mapping_count(), 2);

    // Reverse lookup
    assert_eq!(mapper.get_hostname(&ip1), Some("google.com".to_string()));
    assert_eq!(mapper.get_hostname(&ip2), Some("cloudflare.com".to_string()));

    // Unmapped IP returns None
    let unmapped = Ipv4Addr::new(198, 18, 99, 99);
    assert_eq!(mapper.get_hostname(&unmapped), None);
}

#[test]
fn test_rewrite_socks5_connect_request() {
    let mapper = FakeDnsMapper::new();
    let fake_ip = mapper.get_fake_ip("telegram.org");

    // SOCKS5 CONNECT targeting fake_ip:443
    // VER=5, CMD=1, RSV=0, ATYP=1, IP=[198,18,x,y], PORT=443 ([1, 187])
    let mut req = vec![5, 1, 0, SOCKS5_ATYP_IPV4];
    req.extend_from_slice(&fake_ip.octets());
    req.push(1); // 443 high byte (0x01)
    req.push(187); // 443 low byte (0xBB)

    let rewritten_opt = rewrite_socks5_connect_request(&req, &mapper).expect("rewrite should succeed");
    let rewritten = rewritten_opt.expect("should have rewritten to domain");

    // Expect: [VER=5, CMD=1, RSV=0, ATYP=3, LEN=12, "telegram.org", 1, 187]
    assert_eq!(rewritten[0], 5);
    assert_eq!(rewritten[1], 1);
    assert_eq!(rewritten[2], 0);
    assert_eq!(rewritten[3], SOCKS5_ATYP_DOMAIN);
    assert_eq!(rewritten[4], 12); // length of "telegram.org"
    assert_eq!(&rewritten[5..17], b"telegram.org");
    assert_eq!(rewritten[17], 1);
    assert_eq!(rewritten[18], 187);

    // Real non-fake IP should not be rewritten
    let mut real_req = vec![5, 1, 0, SOCKS5_ATYP_IPV4, 1, 1, 1, 1, 1, 187];
    let real_rewritten = rewrite_socks5_connect_request(&real_req, &mapper).expect("valid check");
    assert_eq!(real_rewritten, None);

    // Non-CONNECT (e.g. UDP ASSOCIATE CMD=3) should not be rewritten
    let mut udp_req = vec![5, 3, 0, SOCKS5_ATYP_IPV4];
    udp_req.extend_from_slice(&fake_ip.octets());
    udp_req.push(1);
    udp_req.push(187);
    assert_eq!(rewrite_socks5_connect_request(&udp_req, &mapper).unwrap(), None);

    // Malformed request returns error
    let malformed = vec![5, 1];
    assert!(rewrite_socks5_connect_request(&malformed, &mapper).is_err());
}

#[test]
fn test_tun_bridge_stats() {
    let stats = TunBridgeStats::new();
    assert_eq!(stats.snapshot(), (0, 0));

    stats.add_upload(1500);
    stats.add_download(4096);
    assert_eq!(stats.snapshot(), (1500, 4096));

    stats.reset();
    assert_eq!(stats.snapshot(), (0, 0));
}
