//! # Raw Packet Crafter
//!
//! Low-level TCP/UDP/ICMP packet construction with manual IP/TCP/UDP header
//! assembly and internet checksum calculation. Ported from IPScanner-main and
//! ipscan-master.
//!
//! Used by:
//! - Port scanners (SYN scan, ACK scan)
//! - Network probers (ICMP ping, TCP RST injection)
//! - DPI desync attacks (wrong-sequence injection)

use std::net::{IpAddr, Ipv4Addr};

/// TCP flag bits.
pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;
}

/// ICMP type codes.
pub mod icmp_types {
    pub const ECHO_REPLY: u8 = 0;
    pub const ECHO_REQUEST: u8 = 8;
    pub const TIME_EXCEEDED: u8 = 11;
    pub const DEST_UNREACHABLE: u8 = 3;
}

/// Computes the RFC 791 one's complement checksum.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Computes the TCP/UDP pseudo-header checksum.
pub fn pseudo_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, segment_len: u16) -> u32 {
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src.octets());
    pseudo[4..8].copy_from_slice(&dst.octets());
    pseudo[8] = 0;
    pseudo[9] = proto;
    pseudo[10..12].copy_from_slice(&segment_len.to_be_bytes());

    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < pseudo.len() {
        sum += u16::from_be_bytes([pseudo[i], pseudo[i + 1]]) as u32;
        i += 2;
    }
    sum
}

/// Builds a raw IPv4 TCP SYN packet.
///
/// Returns the complete raw packet (IP + TCP header) with correct checksums.
pub fn craft_tcp_syn(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
) -> Vec<u8> {
    craft_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, 0, tcp_flags::SYN, 65535, &[])
}

/// Builds a raw IPv4 TCP RST packet.
pub fn craft_tcp_rst(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
) -> Vec<u8> {
    craft_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, 0, tcp_flags::RST | tcp_flags::ACK, 0, &[])
}

/// Builds a raw IPv4 TCP ACK packet with optional payload.
pub fn craft_tcp_ack(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    payload: &[u8],
) -> Vec<u8> {
    craft_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, ack, tcp_flags::ACK | tcp_flags::PSH, 65535, payload)
}

/// Builds a raw IPv4 TCP packet with the specified flags.
pub fn craft_tcp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let total_len = 20 + tcp_len as u16;
    let mut pkt = vec![0u8; total_len as usize];

    // IPv4 Header
    pkt[0] = 0x45; // Version=4, IHL=5
    pkt[1] = 0;    // DSCP/ECN
    pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
    pkt[4..6].copy_from_slice(&rand_id().to_be_bytes());
    pkt[6..8].copy_from_slice(&0u16.to_be_bytes()); // Flags + Fragment offset
    pkt[8] = 64;   // TTL
    pkt[9] = 6;    // Protocol: TCP
    pkt[10..12].copy_from_slice(&[0, 0]); // Checksum (filled later)
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());

    // TCP Header (starts at offset 20)
    let t = 20usize;
    pkt[t..t + 2].copy_from_slice(&src_port.to_be_bytes());
    pkt[t + 2..t + 4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[t + 4..t + 8].copy_from_slice(&seq.to_be_bytes());
    pkt[t + 8..t + 12].copy_from_slice(&ack.to_be_bytes());
    pkt[t + 12] = 0x50; // Data offset: 5 × 4 = 20 bytes, no options
    pkt[t + 13] = flags;
    pkt[t + 14..t + 16].copy_from_slice(&window.to_be_bytes());
    pkt[t + 16..t + 18].copy_from_slice(&[0, 0]); // Checksum placeholder
    pkt[t + 18..t + 20].copy_from_slice(&[0, 0]); // Urgent pointer

    // Payload
    if !payload.is_empty() {
        pkt[t + 20..t + 20 + payload.len()].copy_from_slice(payload);
    }

    // IPv4 header checksum
    let ip_cs = checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_cs.to_be_bytes());

    // TCP checksum (pseudo header + TCP header + payload)
    let mut tcp_data = Vec::with_capacity(tcp_len);
    tcp_data.extend_from_slice(&pkt[t..t + tcp_len]);
    let mut sum = pseudo_checksum(src_ip, dst_ip, 6, tcp_len as u16);

    let mut i = 0;
    while i + 1 < tcp_data.len() {
        sum += u16::from_be_bytes([tcp_data[i], tcp_data[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_data.len() {
        sum += (tcp_data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let tcp_cs = !(sum as u16);
    pkt[t + 16..t + 18].copy_from_slice(&tcp_cs.to_be_bytes());

    pkt
}

/// Builds a raw IPv4 UDP packet.
pub fn craft_udp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let total_len = 20 + udp_len;
    let mut pkt = vec![0u8; total_len as usize];

    // IPv4 Header
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
    pkt[4..6].copy_from_slice(&rand_id().to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17; // UDP
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());

    // UDP Header
    let u = 20usize;
    pkt[u..u + 2].copy_from_slice(&src_port.to_be_bytes());
    pkt[u + 2..u + 4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[u + 4..u + 6].copy_from_slice(&udp_len.to_be_bytes());
    pkt[u + 6..u + 8].copy_from_slice(&[0, 0]); // Checksum (optional for IPv4 UDP)

    // Payload
    pkt[u + 8..u + 8 + payload.len()].copy_from_slice(payload);

    // IPv4 checksum
    let ip_cs = checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_cs.to_be_bytes());

    pkt
}

/// Builds a raw ICMPv4 Echo Request.
pub fn craft_icmp_echo(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, id: u16, seq: u16) -> Vec<u8> {
    let icmp_len = 8usize;
    let total_len = (20 + icmp_len) as u16;
    let mut pkt = vec![0u8; total_len as usize];

    // IPv4 Header
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
    pkt[4..6].copy_from_slice(&rand_id().to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 1; // ICMP
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());

    // ICMP Header
    let i = 20usize;
    pkt[i] = icmp_types::ECHO_REQUEST;
    pkt[i + 1] = 0; // Code
    pkt[i + 2..i + 4].copy_from_slice(&[0, 0]); // Checksum placeholder
    pkt[i + 4..i + 6].copy_from_slice(&id.to_be_bytes());
    pkt[i + 6..i + 8].copy_from_slice(&seq.to_be_bytes());

    // ICMP checksum
    let icmp_cs = checksum(&pkt[i..i + icmp_len]);
    pkt[i + 2..i + 4].copy_from_slice(&icmp_cs.to_be_bytes());

    // IPv4 checksum
    let ip_cs = checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_cs.to_be_bytes());

    pkt
}

/// Returns a random 16-bit identifier for the IP ID field.
fn rand_id() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    (ns ^ (ns >> 16)) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_zero_data() {
        let data = vec![0u8; 10];
        let cs = checksum(&data);
        assert_eq!(cs, 0xFFFF);
    }

    #[test]
    fn test_tcp_syn_packet_structure() {
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        let pkt = craft_tcp_syn(src, dst, 45000, 80, 1000);
        assert_eq!(pkt.len(), 40); // 20 IP + 20 TCP
        assert_eq!(pkt[0] >> 4, 4); // IPv4
        assert_eq!(pkt[9], 6); // Protocol TCP
        assert_eq!(pkt[33], tcp_flags::SYN); // Flags byte
    }

    #[test]
    fn test_udp_packet_structure() {
        let src = Ipv4Addr::new(1, 2, 3, 4);
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        let payload = b"DNS query";
        let pkt = craft_udp_packet(src, dst, 5000, 53, payload);
        assert_eq!(pkt.len(), 20 + 8 + payload.len());
        assert_eq!(pkt[9], 17); // Protocol UDP
    }

    #[test]
    fn test_icmp_echo_structure() {
        let src = Ipv4Addr::new(192, 168, 0, 1);
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        let pkt = craft_icmp_echo(src, dst, 1, 1);
        assert_eq!(pkt.len(), 28); // 20 IP + 8 ICMP
        assert_eq!(pkt[9], 1); // ICMP
        assert_eq!(pkt[20], icmp_types::ECHO_REQUEST);
    }

    #[test]
    fn test_tcp_rst_flags() {
        let src = Ipv4Addr::new(1, 1, 1, 1);
        let dst = Ipv4Addr::new(2, 2, 2, 2);
        let pkt = craft_tcp_rst(src, dst, 12345, 80, 9999);
        // Flags are at TCP header offset 13 = IP offset 20 + 13 = 33
        assert_eq!(pkt[33], tcp_flags::RST | tcp_flags::ACK);
    }
}
