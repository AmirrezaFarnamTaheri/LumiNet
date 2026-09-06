//! Integration tests for Project 06 (Desktop Resilience, Leak Guard, System Proxy & Protocol Escalation).

use lumicore::diagnostics::stun_leak_detector::{
    build_binding_request, evaluate_leak, evaluate_watchdog_quorum, generate_transaction_id,
    parse_binding_response, StunResult, ATTR_XOR_MAPPED_ADDRESS, STUN_BINDING_REQUEST,
    STUN_BINDING_RESPONSE, STUN_MAGIC,
};
use lumicore::platform::system_proxy::{
    build_proxy_string, SYSTEM_PROXY_BYPASS,
};
use lumicore::proxy::multi_protocol_bridge::{
    peer_allowed, sniff_ingress_protocol, IngressProtocol,
};
use lumicore::routing::protocol_escalation::{
    build_direct_plan, build_escalation_plan, next_candidate_protocol, ProtocolKind,
};
use lumicore::security::leak_guard::{
    parse_default_value, parse_reg_value, status, LeakGuard, CHROMIUM_POLICY_NAME,
    CHROMIUM_POLICY_VALUE, FIREFOX_PREF_NAME, FW_RULE, KILL_RULE, SENTINEL_NAME,
    STUN_TURN_PORTS,
};

#[test]
fn test_leak_guard_status_and_disabled_lifecycle() {
    let mut guard = LeakGuard::disabled();
    assert_eq!(guard.rules, 0);
    assert_eq!(guard.kill_rules, 0);
    assert_eq!(guard.policies, 0);
    assert!(guard.edits.is_empty());

    // Disarm without cleanup transfers ownership without releasing system rules
    guard.disarm_without_cleanup();
    assert_eq!(guard.rules, 0);

    // Release for reconnect resets rules while keeping kill-switch active
    guard.kill_rules = 2;
    guard.release_for_reconnect();
    let st = status();
    assert!(st.kill_switch_active);
    assert_eq!(st.firewall_rules, 2);

    // Explicit release clears everything
    guard.release();
    let final_st = status();
    assert!(!final_st.engaged);
    assert_eq!(final_st.firewall_rules, 0);
}

#[test]
fn test_leak_guard_registry_parsers() {
    let sample_chrome_output = "HKEY_CURRENT_USER\\Software\\Policies\\Google\\Chrome\r\n    WebRtcIPHandlingPolicy    REG_SZ    disable_non_proxied_udp\r\n";
    assert_eq!(
        parse_reg_value(sample_chrome_output, CHROMIUM_POLICY_NAME).as_deref(),
        Some(CHROMIUM_POLICY_VALUE)
    );

    let sample_firefox_output = "HKEY_CURRENT_USER\\Software\\Policies\\Mozilla\\Firefox\\Preferences\r\n    media.peerconnection.ice.proxy_only    REG_DWORD    0x1\r\n";
    assert_eq!(
        parse_reg_value(sample_firefox_output, FIREFOX_PREF_NAME).as_deref(),
        Some("0x1")
    );

    let sample_app_path = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe\r\n    (Default)    REG_SZ    C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\r\n";
    assert_eq!(
        parse_default_value(sample_app_path).as_deref(),
        Some("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")
    );
}

#[test]
fn test_leak_guard_constants_and_ports() {
    assert_eq!(FW_RULE, "LumiNet Leak Guard");
    assert_eq!(KILL_RULE, "LumiNet Kill Switch");
    assert_eq!(SENTINEL_NAME, "LumiLeakGuardManaged");

    for required_port in ["3478", "3479", "5349", "5350", "19302-19309"] {
        assert!(
            STUN_TURN_PORTS.contains(required_port),
            "missing port rule for {required_port}"
        );
    }
}

#[test]
fn test_system_proxy_string_and_bypass() {
    let proxy_str = build_proxy_string(10811, 10810);
    assert_eq!(
        proxy_str,
        "http=127.0.0.1:10811;https=127.0.0.1:10811;socks=127.0.0.1:10810"
    );

    // Bypass must isolate local and private IP ranges
    assert!(SYSTEM_PROXY_BYPASS.contains("localhost"));
    assert!(SYSTEM_PROXY_BYPASS.contains("127.*"));
    assert!(SYSTEM_PROXY_BYPASS.contains("10.*"));
    assert!(SYSTEM_PROXY_BYPASS.contains("172.16.*"));
    assert!(SYSTEM_PROXY_BYPASS.contains("192.168.*"));
    assert!(SYSTEM_PROXY_BYPASS.contains("<local>"));
}

#[test]
fn test_multi_protocol_bridge_ingress_sniffing() {
    // SOCKS5 greeting always begins with 0x05
    assert_eq!(sniff_ingress_protocol(0x05), IngressProtocol::Socks5);

    // HTTP methods always start with ASCII alphabetic characters
    assert_eq!(sniff_ingress_protocol(b'C'), IngressProtocol::Http); // CONNECT
    assert_eq!(sniff_ingress_protocol(b'G'), IngressProtocol::Http); // GET
    assert_eq!(sniff_ingress_protocol(b'P'), IngressProtocol::Http); // POST / PUT
    assert_eq!(sniff_ingress_protocol(b'H'), IngressProtocol::Http); // HEAD

    // Invalid / unknown initial bytes
    assert_eq!(sniff_ingress_protocol(0x00), IngressProtocol::Unknown);
    assert_eq!(sniff_ingress_protocol(0xFF), IngressProtocol::Unknown);
}

#[test]
fn test_multi_protocol_bridge_peer_authorization() {
    // Loopback is always allowed
    assert!(peer_allowed("127.0.0.1".parse().unwrap()));
    assert!(peer_allowed("::1".parse().unwrap()));

    // RFC 1918 private subnets are permitted
    assert!(peer_allowed("10.10.10.5".parse().unwrap()));
    assert!(peer_allowed("172.20.1.50".parse().unwrap()));
    assert!(peer_allowed("192.168.0.254".parse().unwrap()));

    // Link-local is permitted
    assert!(peer_allowed("169.254.10.20".parse().unwrap()));

    // Public Internet addresses are rejected to prevent becoming an open relay
    assert!(!peer_allowed("1.1.1.1".parse().unwrap()));
    assert!(!peer_allowed("8.8.8.8".parse().unwrap()));
    assert!(!peer_allowed("140.82.121.4".parse().unwrap()));
}

#[test]
fn test_stun_binary_request_and_response_codec() {
    let txid = generate_transaction_id();
    let req = build_binding_request(&txid);

    // RFC 5389 Header: 2 bytes type (0x0001), 2 bytes length (0x0000), 4 bytes magic (0x2112A442), 12 bytes txid
    assert_eq!(req.len(), 20);
    assert_eq!(u16::from_be_bytes([req[0], req[1]]), STUN_BINDING_REQUEST);
    assert_eq!(u16::from_be_bytes([req[2], req[3]]), 0);
    assert_eq!(u32::from_be_bytes([req[4], req[5], req[6], req[7]]), STUN_MAGIC);
    assert_eq!(&req[8..20], &txid);

    // Synthesize RFC 5389 Binding Response with XOR-MAPPED-ADDRESS
    let mut resp = Vec::new();
    resp.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes()); // 0x0101
    resp.extend_from_slice(&12u16.to_be_bytes()); // total attribute bytes
    resp.extend_from_slice(&STUN_MAGIC.to_be_bytes());
    resp.extend_from_slice(&txid);

    // Add XOR-MAPPED-ADDRESS attribute (Type 0x0020, Length 8)
    resp.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    resp.extend_from_slice(&8u16.to_be_bytes());
    resp.push(0x00); // reserved
    resp.push(0x01); // IPv4
    resp.extend_from_slice(&[0x12, 0x34]); // port

    // Target IP: 203.0.113.195 XORed with STUN_MAGIC
    let target_ip = [203, 0, 113, 195];
    let cookie = STUN_MAGIC.to_be_bytes();
    for i in 0..4 {
        resp.push(target_ip[i] ^ cookie[i]);
    }

    let parsed_ip = parse_binding_response(&resp, &txid);
    assert_eq!(parsed_ip.as_deref(), Some("203.0.113.195"));
}

#[test]
fn test_stun_leak_adjudication() {
    let exit_ip = "198.51.100.25";

    // Case 1: STUN query matches tunnel exit -> Not leaking
    let good_result = Some(StunResult {
        server: "stun.cloudflare.com:3478".into(),
        reflexive_ip: exit_ip.into(),
    });
    let rep1 = evaluate_leak(good_result, Some(exit_ip), false, false);
    assert!(!rep1.leaking);
    assert!(rep1.detail.contains("tunnel exit"));

    // Case 2: STUN query reveals different public IP -> LEAKING
    let leak_result = Some(StunResult {
        server: "stun.l.google.com:19302".into(),
        reflexive_ip: "91.98.0.12".into(),
    });
    let rep2 = evaluate_leak(leak_result, Some(exit_ip), false, false);
    assert!(rep2.leaking);
    assert_eq!(rep2.ip.as_deref(), Some("91.98.0.12"));

    // Case 3: No reply because firewall blocked UDP -> Safe
    let rep3 = evaluate_leak(None, Some(exit_ip), true, false);
    assert!(!rep3.leaking);
    assert!(rep3.detail.contains("firewall kill-switch"));

    // Watchdog quorum: 2 of 3 passes is healthy
    assert!(evaluate_watchdog_quorum(2, 2));
    assert!(evaluate_watchdog_quorum(3, 2));
    assert!(!evaluate_watchdog_quorum(1, 2));
}

#[test]
fn test_protocol_escalation_ladder_and_hostile_network() {
    // Normal direct plan: plain first, hardened second
    let normal_direct = build_direct_plan(ProtocolKind::Masque, 60_000, false);
    assert_eq!(normal_direct.len(), 2);
    assert_eq!(normal_direct[0].label, "MASQUE · as configured");
    assert!(!normal_direct[0].anti_dpi.noise_camouflage);
    assert_eq!(normal_direct[1].label, "MASQUE · hardened anti-DPI");
    assert!(normal_direct[1].anti_dpi.noise_camouflage);

    // Hostile network direct plan: hardened leads immediately
    let hostile_direct = build_direct_plan(ProtocolKind::Masque, 60_000, true);
    assert_eq!(hostile_direct.len(), 2);
    assert_eq!(hostile_direct[0].label, "MASQUE · hardened anti-DPI");
    assert!(hostile_direct[0].anti_dpi.noise_camouflage);
    assert_eq!(hostile_direct[1].label, "MASQUE · as configured");

    // Smart Auto escalation ladder
    let smart_plan = build_escalation_plan(ProtocolKind::Smart, false, 75_000, false);
    assert_eq!(smart_plan[0].protocol, ProtocolKind::Masque);
    assert_eq!(next_candidate_protocol(ProtocolKind::Masque), Some(ProtocolKind::Gool));
    assert_eq!(next_candidate_protocol(ProtocolKind::Gool), Some(ProtocolKind::Wireguard));
    assert_eq!(next_candidate_protocol(ProtocolKind::Wireguard), None);
}
