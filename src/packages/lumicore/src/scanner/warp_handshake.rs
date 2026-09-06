//! Cloudflare WARP Handshake Prober & Endpoint Scanner
//!
//! Ported and unified from `ipscanner-main` (bepass-org) and `warp-plus-master`.
//! Implements WireGuard Noise_IK initiation message crafting, DPI-evasion noise bursts,
//! WARP port tables (54 ports), WARP CIDR prefix pools, and handshake response validation.

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};

/// Standard Cloudflare WARP IPv4 CIDR allocations.
pub const WARP_IPV4_PREFIXES: &[&str] = &[
    "162.159.192.0/24",
    "162.159.195.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
];

/// Standard Cloudflare WARP IPv6 CIDR allocations.
pub const WARP_IPV6_PREFIXES: &[&str] = &[
    "2606:4700:d0::/64",
    "2606:4700:d1::/64",
];

/// The canonical 54 UDP ports supported across Cloudflare WARP edge endpoints.
pub const WARP_PORTS: &[u16] = &[
    500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942,
    943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180,
    1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233,
    4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886,
];

/// Default Cloudflare WARP peer public key (base64 encoded).
pub const DEFAULT_WARP_PEER_PUBLIC_KEY: &str = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";

/// WireGuard protocol message type: Handshake Initiation.
pub const WG_MSG_INITIATION: u32 = 1;
/// WireGuard protocol message type: Handshake Response.
pub const WG_MSG_RESPONSE: u32 = 2;

/// Fixed size of a WireGuard Handshake Initiation packet in bytes.
pub const INITIATION_PACKET_LEN: usize = 148;
/// Expected minimum size of a WireGuard Handshake Response packet in bytes.
pub const RESPONSE_PACKET_LEN: usize = 92;

/// Errors produced during WARP handshake probing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WarpHandshakeError {
    Timeout,
    IoError(String),
    PacketTooShort { expected: usize, found: usize },
    InvalidMessageType { expected: u32, found: u32 },
    SenderIndexMismatch { expected: u32, found: u32 },
    InvalidPublicKeyFormat,
}

impl std::fmt::Display for WarpHandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => write!(f, "warp handshake timed out"),
            Self::IoError(e) => write!(f, "io error: {}", e),
            Self::PacketTooShort { expected, found } => {
                write!(f, "packet too short: expected {} bytes, found {}", expected, found)
            }
            Self::InvalidMessageType { expected, found } => {
                write!(f, "invalid message type: expected {}, found {}", expected, found)
            }
            Self::SenderIndexMismatch { expected, found } => {
                write!(f, "sender index mismatch: expected {}, found {}", expected, found)
            }
            Self::InvalidPublicKeyFormat => write!(f, "invalid base64 public key format"),
        }
    }
}

impl std::error::Error for WarpHandshakeError {}

/// Result of a single WARP endpoint probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarpPingResult {
    pub endpoint: SocketAddr,
    pub rtt_ms: u64,
    pub peer_index: u32,
    pub success: bool,
}

/// Parsed response metadata from an upstream WireGuard / WARP peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarpResponseInfo {
    pub peer_index: u32,
    pub our_index: u32,
    pub encrypted_ephemeral: [u8; 48],
    pub mac1: [u8; 16],
}

/// Selects a random WARP port from the 54 known open edge ports.
pub fn select_random_warp_port() -> u16 {
    let mut rng = rand::thread_rng();
    let idx = rng.gen_range(0..WARP_PORTS.len());
    WARP_PORTS[idx]
}

/// Generates randomized noise packets before the initiation packet to confuse stateful DPI.
pub fn generate_noise_bursts(count: usize, min_size: usize, max_size: usize) -> Vec<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let mut bursts = Vec::with_capacity(count);
    let min_s = min_size.max(1);
    let max_s = max_size.max(min_s);

    for _ in 0..count {
        let size = rng.gen_range(min_s..=max_s);
        let mut packet = vec![0u8; size];
        rng.fill_bytes(&mut packet);
        bursts.push(packet);
    }
    bursts
}

/// Builds a 148-byte WireGuard / WARP Handshake Initiation packet.
pub fn build_initiation_packet(
    sender_index: u32,
    ephemeral_public: &[u8; 32],
    encrypted_static: &[u8; 48],
    encrypted_timestamp: &[u8; 28],
    mac1: &[u8; 16],
) -> [u8; INITIATION_PACKET_LEN] {
    let mut packet = [0u8; INITIATION_PACKET_LEN];

    // Message type (0x01 0x00 0x00 0x00, 4 bytes little-endian)
    packet[0..4].copy_from_slice(&WG_MSG_INITIATION.to_le_bytes());

    // Sender index (4 bytes little-endian)
    packet[4..8].copy_from_slice(&sender_index.to_le_bytes());

    // Unencrypted ephemeral public key (32 bytes)
    packet[8..40].copy_from_slice(ephemeral_public);

    // Encrypted static key (48 bytes: 32 bytes ciphertext + 16 bytes Poly1305 tag)
    packet[40..88].copy_from_slice(encrypted_static);

    // Encrypted timestamp (28 bytes: 12 bytes TAI64N timestamp + 16 bytes Poly1305 tag)
    packet[88..116].copy_from_slice(encrypted_timestamp);

    // MAC1 (16 bytes)
    packet[116..132].copy_from_slice(mac1);

    // MAC2 (16 null bytes for standard initiation without cookie)
    packet[132..148].fill(0);

    packet
}

/// Builds a simulated probe initiation packet with a randomized ephemeral key and index.
pub fn build_probe_packet(sender_index: u32) -> [u8; INITIATION_PACKET_LEN] {
    let mut rng = rand::thread_rng();
    let mut ephem = [0u8; 32];
    rng.fill_bytes(&mut ephem);

    let mut enc_static = [0u8; 48];
    rng.fill_bytes(&mut enc_static);

    let mut enc_time = [0u8; 28];
    rng.fill_bytes(&mut enc_time);

    let mut mac1 = [0u8; 16];
    rng.fill_bytes(&mut mac1);

    build_initiation_packet(sender_index, &ephem, &enc_static, &enc_time, &mac1)
}

/// Validates an incoming WireGuard response packet against the expected sender index.
pub fn validate_handshake_response(
    response: &[u8],
    expected_sender_index: u32,
) -> Result<WarpResponseInfo, WarpHandshakeError> {
    if response.len() < RESPONSE_PACKET_LEN {
        return Err(WarpHandshakeError::PacketTooShort {
            expected: RESPONSE_PACKET_LEN,
            found: response.len(),
        });
    }

    let msg_type = u32::from_le_bytes(
        response[0..4]
            .try_into()
            .map_err(|_| WarpHandshakeError::PacketTooShort {
                expected: 4,
                found: response.len(),
            })?,
    );

    if msg_type != WG_MSG_RESPONSE {
        return Err(WarpHandshakeError::InvalidMessageType {
            expected: WG_MSG_RESPONSE,
            found: msg_type,
        });
    }

    let peer_index = u32::from_le_bytes(response[4..8].try_into().unwrap());
    let our_index = u32::from_le_bytes(response[8..12].try_into().unwrap());

    if our_index != expected_sender_index {
        return Err(WarpHandshakeError::SenderIndexMismatch {
            expected: expected_sender_index,
            found: our_index,
        });
    }

    let mut encrypted_ephemeral = [0u8; 48];
    encrypted_ephemeral.copy_from_slice(&response[12..60]);

    let mut mac1 = [0u8; 16];
    mac1.copy_from_slice(&response[60..76]);

    Ok(WarpResponseInfo {
        peer_index,
        our_index,
        encrypted_ephemeral,
        mac1,
    })
}

/// Probes a Cloudflare WARP endpoint asynchronously via UDP.
pub async fn probe_warp_endpoint(
    endpoint: SocketAddr,
    sender_index: u32,
    timeout_dur: Duration,
    send_noise: bool,
) -> Result<WarpPingResult, WarpHandshakeError> {
    let socket = tokio::net::UdpSocket::bind(if endpoint.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" })
        .await
        .map_err(|e| WarpHandshakeError::IoError(e.to_string()))?;

    socket
        .connect(endpoint)
        .await
        .map_err(|e| WarpHandshakeError::IoError(e.to_string()))?;

    // Pre-handshake noise injection
    if send_noise {
        let noise_packets = generate_noise_bursts(2, 20, 80);
        for packet in noise_packets {
            let _ = socket.send(&packet).await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    let probe_packet = build_probe_packet(sender_index);
    let start = Instant::now();

    socket
        .send(&probe_packet)
        .await
        .map_err(|e| WarpHandshakeError::IoError(e.to_string()))?;

    let mut buf = [0u8; 256];
    let recv_fut = socket.recv(&mut buf);

    let n = tokio::time::timeout(timeout_dur, recv_fut)
        .await
        .map_err(|_| WarpHandshakeError::Timeout)?
        .map_err(|e| WarpHandshakeError::IoError(e.to_string()))?;

    let rtt = start.elapsed();
    let resp_info = validate_handshake_response(&buf[..n], sender_index)?;

    Ok(WarpPingResult {
        endpoint,
        rtt_ms: rtt.as_millis() as u64,
        peer_index: resp_info.peer_index,
        success: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_warp_ports_table() {
        assert_eq!(WARP_PORTS.len(), 54);
        assert!(WARP_PORTS.contains(&500));
        assert!(WARP_PORTS.contains(&8886));
        assert!(WARP_PORTS.contains(&4500));
    }

    #[test]
    fn test_random_warp_port() {
        let port = select_random_warp_port();
        assert!(WARP_PORTS.contains(&port));
    }

    #[test]
    fn test_noise_burst_generation() {
        let bursts = generate_noise_bursts(3, 15, 60);
        assert_eq!(bursts.len(), 3);
        for b in bursts {
            assert!(b.len() >= 15 && b.len() <= 60);
        }
    }

    #[test]
    fn test_initiation_packet_structure() {
        let packet = build_probe_packet(28);
        assert_eq!(packet.len(), INITIATION_PACKET_LEN);
        // First 4 bytes must be message type 1
        assert_eq!(&packet[0..4], &[1, 0, 0, 0]);
        // Bytes 4..8 must be sender index 28
        assert_eq!(&packet[4..8], &[28, 0, 0, 0]);
        // Bytes 132..148 must be zeroes (MAC2)
        assert_eq!(&packet[132..148], &[0u8; 16]);
    }

    #[test]
    fn test_validate_response_success() {
        let mut mock_resp = [0u8; 92];
        // Message type = 2
        mock_resp[0..4].copy_from_slice(&2u32.to_le_bytes());
        // Peer index = 1001
        mock_resp[4..8].copy_from_slice(&1001u32.to_le_bytes());
        // Our receiver index = 28
        mock_resp[8..12].copy_from_slice(&28u32.to_le_bytes());
        // Ephemeral
        mock_resp[12..60].fill(0xAA);
        // MAC1
        mock_resp[60..76].fill(0xBB);

        let res = validate_handshake_response(&mock_resp, 28).expect("valid response");
        assert_eq!(res.peer_index, 1001);
        assert_eq!(res.our_index, 28);
        assert_eq!(res.encrypted_ephemeral[0], 0xAA);
        assert_eq!(res.mac1[0], 0xBB);
    }

    #[test]
    fn test_validate_response_mismatch_index() {
        let mut mock_resp = [0u8; 92];
        mock_resp[0..4].copy_from_slice(&2u32.to_le_bytes());
        mock_resp[4..8].copy_from_slice(&1001u32.to_le_bytes());
        mock_resp[8..12].copy_from_slice(&99u32.to_le_bytes()); // mismatch!

        let err = validate_handshake_response(&mock_resp, 28).unwrap_err();
        assert_eq!(
            err,
            WarpHandshakeError::SenderIndexMismatch {
                expected: 28,
                found: 99
            }
        );
    }

    #[test]
    fn test_validate_response_short() {
        let mock_resp = [0u8; 50];
        let err = validate_handshake_response(&mock_resp, 28).unwrap_err();
        assert_eq!(
            err,
            WarpHandshakeError::PacketTooShort {
                expected: 92,
                found: 50
            }
        );
    }
}
