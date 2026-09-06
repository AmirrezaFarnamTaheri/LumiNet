//! RFC 5389 STUN Binary Protocol Client and Active WebRTC Leak Detector.
//!
//! Provides deterministic active leak verification:
//! 1. RFC 5389 binary encoder/decoder: constructs Binding Requests with 96-bit transaction IDs
//!    and decodes XOR-MAPPED-ADDRESS (`0x0020`) and MAPPED-ADDRESS (`0x0001`) attributes.
//! 2. Active WebRTC srflx probe: Transmits raw UDP STUN datagrams to public STUN servers
//!    (`stun.l.google.com:19302`, `stun.cloudflare.com:3478`, etc.) from the physical interface.
//! 3. Ground-truth leak adjudication: compares reflexive IP against the expected tunnel exit IP.
//!    If raw UDP bypasses the tunnel and reveals the user's ISP IP, flags `leaking: true`.
//! 4. 5-Stage gating diagnostics: Defines the standard connection readiness pipeline
//!    (`socks_port`, `socks_handshake`, `tcp_via_proxy`, `dns_http_via_tunnel`, `webrtc_udp_leak`).
//! 5. Multi-target watchdog quorum: verifies 3 independent endpoints, requiring >= 2 passes to prevent
//!    unnecessary tunnel tear-downs during transient CDN edge interruptions.

use std::net::{Ipv4Addr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const STUN_MAGIC: u32 = 0x2112_A442;
pub const STUN_BINDING_REQUEST: u16 = 0x0001;
pub const STUN_BINDING_RESPONSE: u16 = 0x0101;
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

pub const DEFAULT_STUN_SERVERS: [&str; 4] = [
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "global.stun.twilio.com:3478",
    "stun.voip.blackberry.com:3478",
];

pub const C_PORT: &str = "socks_port";
pub const C_HANDSHAKE: &str = "socks_handshake";
pub const C_TCP: &str = "tcp_via_proxy";
pub const C_DNS: &str = "dns_http_via_tunnel";
pub const C_LEAK: &str = "webrtc_udp_leak";

/// Generates unique 96-bit transaction ID (8-byte epoch nanos + 4-byte atomic seq).
pub fn generate_transaction_id() -> [u8; 12] {
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut id = [0u8; 12];
    id[..8].copy_from_slice(&nanos.to_be_bytes());
    id[8..].copy_from_slice(&seq.to_be_bytes());
    id
}

/// Constructs RFC 5389 20-byte Binding Request header.
pub fn build_binding_request(txid: &[u8; 12]) -> Vec<u8> {
    let mut req = Vec::with_capacity(20);
    req.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    req.extend_from_slice(&0u16.to_be_bytes()); // Length of attributes = 0
    req.extend_from_slice(&STUN_MAGIC.to_be_bytes());
    req.extend_from_slice(txid);
    req
}

/// Decodes an RFC 5389 Binding Response, prioritizing XOR-MAPPED-ADDRESS over MAPPED-ADDRESS.
pub fn parse_binding_response(msg: &[u8], txid: &[u8; 12]) -> Option<String> {
    if msg.len() < 20 {
        return None;
    }
    if u16::from_be_bytes([msg[0], msg[1]]) != STUN_BINDING_RESPONSE {
        return None;
    }
    if u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]) != STUN_MAGIC {
        return None;
    }
    if msg[8..20] != *txid {
        return None; // Mismatched or spoofed transaction ID
    }

    let declared_len = u16::from_be_bytes([msg[2], msg[3]]) as usize;
    let end = (20 + declared_len).min(msg.len());

    let mut i = 20;
    let mut fallback_mapped: Option<String> = None;

    while i + 4 <= end {
        let attr_type = u16::from_be_bytes([msg[i], msg[i + 1]]);
        let attr_len = u16::from_be_bytes([msg[i + 2], msg[i + 3]]) as usize;
        let start = i + 4;
        let stop = start + attr_len;
        if stop > end {
            break;
        }

        let body = &msg[start..stop];
        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                if let Some(ip) = xor_mapped_v4(body) {
                    return Some(ip);
                }
            }
            ATTR_MAPPED_ADDRESS => {
                if fallback_mapped.is_none() {
                    fallback_mapped = mapped_v4(body);
                }
            }
            _ => {}
        }

        // RFC 5389 attributes are padded to 4-byte boundaries
        i = stop + ((4 - (attr_len % 4)) % 4);
    }

    fallback_mapped
}

/// Decodes IPv4 XOR-MAPPED-ADDRESS attribute body by XOR-unmasking with the magic cookie.
pub fn xor_mapped_v4(body: &[u8]) -> Option<String> {
    if body.len() < 8 || body[1] != 0x01 {
        return None; // Only IPv4 is decoded here
    }
    let cookie = STUN_MAGIC.to_be_bytes();
    let mut octets = [0u8; 4];
    for k in 0..4 {
        octets[k] = body[4 + k] ^ cookie[k];
    }
    Some(Ipv4Addr::from(octets).to_string())
}

/// Decodes plain IPv4 MAPPED-ADDRESS attribute body.
pub fn mapped_v4(body: &[u8]) -> Option<String> {
    if body.len() < 8 || body[1] != 0x01 {
        return None;
    }
    Some(Ipv4Addr::new(body[4], body[5], body[6], body[7]).to_string())
}

/// Result of an active WebRTC STUN reflexivity query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunResult {
    pub server: String,
    pub reflexive_ip: String,
}

/// Transmits a UDP STUN query to a single server.
pub fn query_stun_server(server: &str, timeout: Duration) -> Option<String> {
    let addr = server.to_socket_addrs().ok()?.find(|a| a.is_ipv4())?;
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    sock.set_read_timeout(Some(timeout)).ok()?;
    sock.set_write_timeout(Some(timeout)).ok()?;

    let txid = generate_transaction_id();
    let req = build_binding_request(&txid);
    sock.send_to(&req, addr).ok()?;

    let mut buf = [0u8; 512];
    let (n, from) = sock.recv_from(&mut buf).ok()?;
    if from.ip() != addr.ip() {
        return None;
    }
    parse_binding_response(&buf[..n], &txid)
}

/// Probes the public STUN server fleet until an address is found or all time out.
pub fn probe_stun_reflexive_ip(timeout: Duration) -> Option<StunResult> {
    for server in DEFAULT_STUN_SERVERS {
        if let Some(ip) = query_stun_server(server, timeout) {
            return Some(StunResult {
                server: server.to_string(),
                reflexive_ip: ip,
            });
        }
    }
    None
}

/// Report summarizing WebRTC/UDP leak assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakReport {
    pub leaking: bool,
    pub ip: Option<String>,
    pub server: Option<String>,
    pub detail: String,
}

/// Evaluates leak status given observed STUN result and expected tunnel exit IP.
pub fn evaluate_leak(
    stun_res: Option<StunResult>,
    exit_ip: Option<&str>,
    firewall_active: bool,
    browser_policy_active: bool,
) -> LeakReport {
    match stun_res {
        None => LeakReport {
            leaking: false,
            ip: None,
            server: None,
            detail: if firewall_active {
                "No reply: Windows firewall kill-switch successfully blocked direct UDP".to_string()
            } else if browser_policy_active {
                "No reply: browser policy blocked direct UDP".to_string()
            } else {
                "No reply: direct UDP is blocked".to_string()
            },
        },
        Some(r) => {
            let via_tunnel = exit_ip.map(|e| e == r.reflexive_ip).unwrap_or(false);
            let browser_policy_only = !firewall_active && browser_policy_active;
            let leaking = !via_tunnel && !browser_policy_only;

            LeakReport {
                leaking,
                ip: Some(r.reflexive_ip.clone()),
                server: Some(r.server.clone()),
                detail: if via_tunnel {
                    format!("STUN answered with the tunnel exit ({})", r.reflexive_ip)
                } else if browser_policy_only {
                    "Browser WebRTC policy is active; non-browser test tool reached STUN".to_string()
                } else {
                    format!("Real client IP {} reachable via STUN server {}", r.reflexive_ip, r.server)
                },
            }
        }
    }
}

/// Evaluates watchdog quorum: requires at least `min_passes` out of `results`.
pub fn evaluate_watchdog_quorum(passes: usize, min_passes: usize) -> bool {
    passes >= min_passes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_request_structure() {
        let txid = [42u8; 12];
        let req = build_binding_request(&txid);
        assert_eq!(req.len(), 20);
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), STUN_BINDING_REQUEST);
        assert_eq!(u16::from_be_bytes([req[2], req[3]]), 0);
        assert_eq!(u32::from_be_bytes([req[4], req[5], req[6], req[7]]), STUN_MAGIC);
        assert_eq!(&req[8..20], &txid);
    }

    #[test]
    fn decodes_xor_mapped_v4() {
        let txid = [7u8; 12];
        let mut msg: Vec<u8> = Vec::new();
        msg.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        msg.extend_from_slice(&12u16.to_be_bytes()); // length
        msg.extend_from_slice(&STUN_MAGIC.to_be_bytes());
        msg.extend_from_slice(&txid);

        msg.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        msg.extend_from_slice(&8u16.to_be_bytes());
        msg.push(0x00); // reserved
        msg.push(0x01); // family IPv4
        msg.extend_from_slice(&[0x00, 0x00]); // port

        // 198.51.100.1 XORed with magic cookie
        let ip = [198, 51, 100, 1];
        let cookie = STUN_MAGIC.to_be_bytes();
        for k in 0..4 {
            msg.push(ip[k] ^ cookie[k]);
        }

        let parsed = parse_binding_response(&msg, &txid);
        assert_eq!(parsed.as_deref(), Some("198.51.100.1"));
    }

    #[test]
    fn rejects_mismatched_transaction_id() {
        let txid = [1u8; 12];
        let bad_txid = [2u8; 12];
        let mut msg: Vec<u8> = Vec::new();
        msg.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&STUN_MAGIC.to_be_bytes());
        msg.extend_from_slice(&bad_txid);

        assert!(parse_binding_response(&msg, &txid).is_none());
    }

    #[test]
    fn evaluate_leak_scenarios() {
        // Scenario 1: Blocked by firewall (no reply) -> safe
        let rep1 = evaluate_leak(None, Some("104.28.1.1"), true, false);
        assert!(!rep1.leaking);

        // Scenario 2: STUN returned tunnel exit IP -> safe
        let rep2 = evaluate_leak(
            Some(StunResult {
                server: "stun.cloudflare.com:3478".into(),
                reflexive_ip: "104.28.1.1".into(),
            }),
            Some("104.28.1.1"),
            false,
            false,
        );
        assert!(!rep2.leaking);

        // Scenario 3: STUN returned external ISP IP -> LEAKING
        let rep3 = evaluate_leak(
            Some(StunResult {
                server: "stun.cloudflare.com:3478".into(),
                reflexive_ip: "2.176.0.1".into(),
            }),
            Some("104.28.1.1"),
            false,
            false,
        );
        assert!(rep3.leaking);
    }

    #[test]
    fn watchdog_quorum_requires_threshold() {
        assert!(evaluate_watchdog_quorum(3, 2));
        assert!(evaluate_watchdog_quorum(2, 2));
        assert!(!evaluate_watchdog_quorum(1, 2));
    }
}
