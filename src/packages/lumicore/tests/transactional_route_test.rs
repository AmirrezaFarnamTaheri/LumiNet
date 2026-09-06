//! # Transactional Routing & Stale Adapter Recovery Tests
//!
//! 1. Transactional Routing Sessions: Unique session ID / TUN interface naming, atomic JSON serialization.
//! 2. Stale Adapter & Crash Recovery: Scanning and detecting abandoned session directories.
//! 3. sing-box 1.13.x Routing Configuration: Inbound TUN, SOCKS5 bridge outbound, DoH hijack, split-tunneling.
//! 4. SOCKS5 Handshake Verifier: Validating listener readiness with initial version negotiation bytes.

use std::fs;
use std::io::Cursor;
use std::net::SocketAddr;
use std::path::PathBuf;

use lumicore::platform::{
    atomic_write_json, build_singbox_tun_config, detect_stale_sessions, generate_session_id,
    generate_tun_name, verify_socks5_handshake_bytes, Ipv6Behavior, RoutingConfig, RoutingError,
    RoutingMode,
};
use serde_json::json;

// ============================================================================
// 1. Transactional Routing Session & Interface Naming Tests
// ============================================================================

#[test]
fn test_session_id_and_tun_name_uniqueness() {
    let pid = 12345;
    let sid1 = generate_session_id(pid);
    let tun_name = generate_tun_name("LumiTun", pid, &sid1);

    assert!(sid1.starts_with("12345-"));
    assert!(tun_name.starts_with("LumiTun-2345-"));
    assert!(tun_name.len() <= 32);
}

#[test]
fn test_routing_config_validation_rules() {
    let loopback: SocketAddr = "127.0.0.1:1819".parse().unwrap();
    let base_dir = PathBuf::from("/tmp/luminet_routing_test");
    let mut config = RoutingConfig::new(loopback, base_dir.clone(), RoutingMode::Full).unwrap();

    assert!(config.validate().is_ok());

    // Test invalid MTU < 1280
    config.tun_mtu = 1200;
    assert!(matches!(config.validate(), Err(RoutingError::Validation(_))));

    // Test valid MTU
    config.tun_mtu = 1500;
    assert!(config.validate().is_ok());

    // Test rejection of non-loopback SOCKS5
    let remote: SocketAddr = "10.0.0.1:1819".parse().unwrap();
    assert!(RoutingConfig::new(remote, base_dir, RoutingMode::Full).is_err());
}

// ============================================================================
// 2. sing-box 1.13.x Routing Generator Tests
// ============================================================================

#[test]
fn test_singbox_routing_generator_modes() {
    let loopback: SocketAddr = "127.0.0.1:1819".parse().unwrap();
    let base_dir = PathBuf::from("/tmp/luminet_routing_test");

    // Mode 1: BypassLocal + IPv6 Block
    let mut cfg_local = RoutingConfig::new(loopback, base_dir.clone(), RoutingMode::BypassLocal).unwrap();
    cfg_local.ipv6_behavior = Ipv6Behavior::Block;
    cfg_local.route_exclusions.push("198.51.100.0/24".into());

    let json_local = build_singbox_tun_config(&cfg_local);

    // Verify inbound TUN
    let inbounds = json_local["inbounds"].as_array().unwrap();
    assert_eq!(inbounds[0]["type"], "tun");
    assert_eq!(inbounds[0]["interface_name"], cfg_local.tun_interface);
    assert_eq!(inbounds[0]["strict_route"], true); // DNS leak protection

    // Verify outbound SOCKS
    let outbounds = json_local["outbounds"].as_array().unwrap();
    assert_eq!(outbounds[0]["type"], "socks");
    assert_eq!(outbounds[0]["server"], "127.0.0.1");
    assert_eq!(outbounds[0]["server_port"], 1819);

    // Verify routing rules
    let rules = json_local["route"]["rules"].as_array().unwrap();
    assert!(rules.iter().any(|r| r["ip_is_private"] == json!(true) && r["outbound"] == "direct"));
    assert!(rules.iter().any(|r| r["ip_version"] == json!(6) && r["action"] == "reject"));
    assert!(rules.iter().any(|r| r["ip_cidr"] == json!(["198.51.100.0/24"])));
    assert_eq!(json_local["route"]["final"], "socks-out");

    // Mode 2: SplitInclude
    let mut cfg_split = RoutingConfig::new(loopback, base_dir, RoutingMode::SplitInclude).unwrap();
    cfg_split.split_applications.push("C:\\Browser\\browser.exe".into());

    let json_split = build_singbox_tun_config(&cfg_split);
    let split_rules = json_split["route"]["rules"].as_array().unwrap();
    assert!(split_rules.iter().any(|r| r["process_path"] == json!(["C:/Browser/browser.exe"]) && r["outbound"] == "socks-out"));
    assert_eq!(json_split["route"]["final"], "direct");
}

// ============================================================================
// 3. Atomic JSON & Stale Session Recovery Tests
// ============================================================================

#[test]
fn test_atomic_json_and_stale_session_discovery() {
    let test_dir = std::env::temp_dir().join(format!("luminet_route_rec_{}", std::process::id()));
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).unwrap();

    // Create an active session directory
    let active_dir = test_dir.join("active-session");
    fs::create_dir_all(&active_dir).unwrap();
    atomic_write_json(&active_dir.join("status.json"), &json!({
        "state": "connected",
        "message": "Tunnel running"
    })).unwrap();

    // Create a stale session directory (crashed during preparing)
    let stale_dir1 = test_dir.join("stale-session-1");
    fs::create_dir_all(&stale_dir1).unwrap();
    atomic_write_json(&stale_dir1.join("status.json"), &json!({
        "state": "preparing",
        "message": "Crashed"
    })).unwrap();

    // Create another stale session directory (error state)
    let stale_dir2 = test_dir.join("stale-session-2");
    fs::create_dir_all(&stale_dir2).unwrap();
    atomic_write_json(&stale_dir2.join("status.json"), &json!({
        "state": "error",
        "message": "Adapter failed"
    })).unwrap();

    let stale = detect_stale_sessions(&test_dir);
    assert_eq!(stale.len(), 2);
    assert!(stale.iter().any(|p| p.ends_with("stale-session-1")));
    assert!(stale.iter().any(|p| p.ends_with("stale-session-2")));
    assert!(!stale.iter().any(|p| p.ends_with("active-session")));

    let _ = fs::remove_dir_all(test_dir);
}

// ============================================================================
// 4. SOCKS5 Handshake Verification Tests
// ============================================================================

#[test]
fn test_socks5_handshake_positive_and_negative() {
    struct MockStream {
        read_data: Cursor<Vec<u8>>,
        write_data: Vec<u8>,
    }

    impl std::io::Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.read_data.read(buf)
        }
    }

    impl std::io::Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.write_data.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    // Test successful 0x05 0x00 response
    let mut good_stream = MockStream {
        read_data: Cursor::new(vec![0x05, 0x00]),
        write_data: Vec::new(),
    };
    assert_eq!(verify_socks5_handshake_bytes(&mut good_stream).unwrap(), true);
    assert_eq!(good_stream.write_data, vec![0x05, 0x01, 0x00]);

    // Test rejection 0x05 0xFF (no acceptable methods)
    let mut bad_stream = MockStream {
        read_data: Cursor::new(vec![0x05, 0xff]),
        write_data: Vec::new(),
    };
    assert_eq!(verify_socks5_handshake_bytes(&mut bad_stream).unwrap(), false);
}
