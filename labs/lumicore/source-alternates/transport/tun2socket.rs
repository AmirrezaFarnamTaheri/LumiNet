//! # TUN-to-Socket TCP/UDP Redirector
//!
//! Routes all traffic coming from the system TUN interface (virtual layer-3 device)
//! to a SOCKS5 proxy or direct socket, ported from tun2socket-main.
//!
//! Architecture:
//! - TUN fd receives raw IPv4/IPv6 packets from the OS.
//! - TCP sessions: intercept SYN, complete three-way handshake on-device,
//!   then open a SOCKS5 connection to the real destination.
//! - UDP sessions: NAT table maps 5-tuple to outbound sockets.
//!
//! Wire path:
//!   App → TUN(fd) → [this module] → SOCKS5/direct socket → Internet

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Ethertype / IP version codes.
const IPV4_VERSION: u8 = 4;
const IPV6_VERSION: u8 = 6;
/// IP protocol numbers.
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMP: u8 = 1;

/// Minimum IPv4 header size (no options).
const IPV4_MIN_HDR: usize = 20;
/// Minimum IPv6 header size.
const IPV6_MIN_HDR: usize = 40;

/// Parsed representation of an IPv4 header.
#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub tos: u8,
    pub total_len: u16,
    pub id: u16,
    pub flags_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub header_len: usize,
}

impl Ipv4Header {
    /// Parses an IPv4 header from a raw packet buffer.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < IPV4_MIN_HDR {
            return None;
        }
        if (buf[0] >> 4) != IPV4_VERSION {
            return None;
        }
        let ihl = (buf[0] & 0x0F) as usize * 4;
        if ihl < IPV4_MIN_HDR || buf.len() < ihl {
            return None;
        }
        Some(Self {
            version_ihl: buf[0],
            tos: buf[1],
            total_len: u16::from_be_bytes([buf[2], buf[3]]),
            id: u16::from_be_bytes([buf[4], buf[5]]),
            flags_offset: u16::from_be_bytes([buf[6], buf[7]]),
            ttl: buf[8],
            protocol: buf[9],
            checksum: u16::from_be_bytes([buf[10], buf[11]]),
            src: Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]),
            dst: Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]),
            header_len: ihl,
        })
    }

    /// Writes a new IPv4 checksum over the header in-place.
    pub fn fix_checksum(buf: &mut [u8]) {
        if buf.len() < IPV4_MIN_HDR {
            return;
        }
        let ihl = (buf[0] & 0x0F) as usize * 4;
        buf[10] = 0;
        buf[11] = 0;
        let sum = internet_checksum(&buf[..ihl]);
        buf[10] = (sum >> 8) as u8;
        buf[11] = (sum & 0xFF) as u8;
    }
}

/// Parses the destination port from a TCP/UDP payload that follows the IP header.
pub fn extract_transport_port(ip_payload: &[u8], is_tcp: bool) -> Option<(u16, u16)> {
    if ip_payload.len() < 4 {
        return None;
    }
    let src_port = u16::from_be_bytes([ip_payload[0], ip_payload[1]]);
    let dst_port = u16::from_be_bytes([ip_payload[2], ip_payload[3]]);
    let _ = is_tcp; // reserved for future TCP-specific validation
    Some((src_port, dst_port))
}

/// Computes the RFC 791 Internet checksum over a byte slice.
pub fn internet_checksum(data: &[u8]) -> u16 {
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

/// 5-tuple flow key for NAT tracking.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: u8,
}

/// A single NAT flow entry.
pub struct FlowEntry {
    pub mapped_port: u16,
    pub last_active: Instant,
}

/// TUN-to-socket NAT mapper.
pub struct Tun2SocketNat {
    flows: HashMap<FlowKey, FlowEntry>,
    port_map: HashMap<u16, FlowKey>, // reverse: mapped_port → original flow
    next_port: u16,
    timeout: Duration,
}

impl Tun2SocketNat {
    pub fn new(timeout: Duration) -> Self {
        Self {
            flows: HashMap::new(),
            port_map: HashMap::new(),
            next_port: 10_000,
            timeout,
        }
    }

    /// Allocates or retrieves a mapped port for an outgoing flow.
    pub fn get_or_create_outbound(&mut self, key: FlowKey) -> u16 {
        if let Some(entry) = self.flows.get_mut(&key) {
            entry.last_active = Instant::now();
            return entry.mapped_port;
        }
        let port = self.next_port;
        self.next_port = if self.next_port >= 65_000 { 10_000 } else { self.next_port + 1 };

        self.port_map.insert(port, key.clone());
        self.flows.insert(key, FlowEntry { mapped_port: port, last_active: Instant::now() });
        port
    }

    /// Reverse-maps an inbound packet's destination port to the original flow.
    pub fn lookup_inbound(&self, dst_port: u16) -> Option<&FlowKey> {
        self.port_map.get(&dst_port)
    }

    /// Evicts timed-out flow entries.
    pub fn evict_stale(&mut self) {
        let now = Instant::now();
        let timeout = self.timeout;
        let stale: Vec<FlowKey> = self.flows.iter()
            .filter(|(_, e)| now.duration_since(e.last_active) > timeout)
            .map(|(k, _)| k.clone())
            .collect();
        for key in stale {
            if let Some(entry) = self.flows.remove(&key) {
                self.port_map.remove(&entry.mapped_port);
            }
        }
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
}

/// Classifies a raw packet read from a TUN device.
#[derive(Debug, Clone)]
pub enum TunPacket {
    Tcp {
        src: SocketAddr,
        dst: SocketAddr,
        payload: Vec<u8>,
    },
    Udp {
        src: SocketAddr,
        dst: SocketAddr,
        payload: Vec<u8>,
    },
    Icmp {
        src: IpAddr,
        dst: IpAddr,
        payload: Vec<u8>,
    },
    Unknown,
}

/// Classifies a raw TUN packet.
pub fn classify_tun_packet(buf: &[u8]) -> TunPacket {
    if buf.len() < IPV4_MIN_HDR {
        return TunPacket::Unknown;
    }
    let version = buf[0] >> 4;
    if version != IPV4_VERSION {
        return TunPacket::Unknown; // IPv6 classification separate
    }
    let hdr = match Ipv4Header::parse(buf) {
        Some(h) => h,
        None => return TunPacket::Unknown,
    };
    let payload = &buf[hdr.header_len..];
    let src_ip = IpAddr::V4(hdr.src);
    let dst_ip = IpAddr::V4(hdr.dst);

    match hdr.protocol {
        PROTO_TCP => {
            if let Some((sp, dp)) = extract_transport_port(payload, true) {
                TunPacket::Tcp {
                    src: SocketAddr::new(src_ip, sp),
                    dst: SocketAddr::new(dst_ip, dp),
                    payload: payload.to_vec(),
                }
            } else {
                TunPacket::Unknown
            }
        }
        PROTO_UDP => {
            if let Some((sp, dp)) = extract_transport_port(payload, false) {
                TunPacket::Udp {
                    src: SocketAddr::new(src_ip, sp),
                    dst: SocketAddr::new(dst_ip, dp),
                    payload: if payload.len() > 8 { payload[8..].to_vec() } else { vec![] },
                }
            } else {
                TunPacket::Unknown
            }
        }
        PROTO_ICMP => TunPacket::Icmp {
            src: src_ip,
            dst: dst_ip,
            payload: payload.to_vec(),
        },
        _ => TunPacket::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_internet_checksum_zero_data() {
        let data = vec![0u8; 20];
        // Checksum of all zeros
        let cs = internet_checksum(&data);
        // All zeros → sum = 0 → NOT = 0xFFFF
        assert_eq!(cs, 0xFFFF);
    }

    #[test]
    fn test_ipv4_header_parse() {
        // Minimal valid IPv4 header (no options, version=4, IHL=5)
        let mut hdr = vec![0u8; 20];
        hdr[0] = 0x45; // Version=4, IHL=5
        hdr[2..4].copy_from_slice(&20u16.to_be_bytes()); // total len
        hdr[8] = 64; // TTL
        hdr[9] = 6;  // TCP
        hdr[12..16].copy_from_slice(&[192, 168, 1, 1]);
        hdr[16..20].copy_from_slice(&[10, 0, 0, 1]);

        let parsed = Ipv4Header::parse(&hdr).unwrap();
        assert_eq!(parsed.protocol, 6);
        assert_eq!(parsed.src, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(parsed.dst, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_nat_get_or_create() {
        let mut nat = Tun2SocketNat::new(Duration::from_secs(30));
        let key = FlowKey {
            src_ip: "192.168.1.1".parse().unwrap(),
            src_port: 5000,
            dst_ip: "8.8.8.8".parse().unwrap(),
            dst_port: 53,
            protocol: PROTO_UDP,
        };
        let port1 = nat.get_or_create_outbound(key.clone());
        let port2 = nat.get_or_create_outbound(key.clone());
        assert_eq!(port1, port2);
        assert_eq!(nat.flow_count(), 1);
    }

    #[test]
    fn test_classify_udp_packet() {
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45; // IPv4, IHL=5
        pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
        pkt[8] = 64; // TTL
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&[1, 2, 3, 4]);
        pkt[16..20].copy_from_slice(&[5, 6, 7, 8]);
        pkt[20..22].copy_from_slice(&1234u16.to_be_bytes()); // src port
        pkt[22..24].copy_from_slice(&53u16.to_be_bytes()); // dst port
        pkt[24..26].copy_from_slice(&8u16.to_be_bytes()); // UDP length = 8 (header only)

        let classified = classify_tun_packet(&pkt);
        assert!(matches!(classified, TunPacket::Udp { .. }));
    }
}
