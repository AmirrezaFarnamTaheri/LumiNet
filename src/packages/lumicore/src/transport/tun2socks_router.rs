//! Tun2Socks Virtual Router & UDPGW Protocol Framing
//!
//! Provides userspace IP packet demultiplexing, NAT session table tracking,
//! transparent DNS interception, and BadVPN UDP Gateway (udpgw) protocol framing.
//!
//! Conforms to strict architectural isolation rules: zero vendor prefixes.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

pub const UDPGW_CLIENT_FLAG_IPV6: u8 = 0x01;
pub const UDPGW_CLIENT_FLAG_DNS: u8 = 0x02;
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 60;
pub const MAX_FRAME_SIZE: usize = 65535;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Tun2SocksError {
    PacketTooShort,
    InvalidIpVersion(u8),
    UnsupportedProtocol(u8),
    InvalidUdpGwHeader,
    PayloadExceedsLimit(usize),
}

impl std::fmt::Display for Tun2SocksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PacketTooShort => write!(f, "tun2socks: packet buffer is too short"),
            Self::InvalidIpVersion(v) => write!(f, "tun2socks: invalid IP version {}", v),
            Self::UnsupportedProtocol(p) => write!(f, "tun2socks: unsupported L4 protocol {}", p),
            Self::InvalidUdpGwHeader => write!(f, "tun2socks: malformed UDPGW framing header"),
            Self::PayloadExceedsLimit(sz) => write!(f, "tun2socks: payload size {} exceeds {}", sz, MAX_FRAME_SIZE),
        }
    }
}

impl std::error::Error for Tun2SocksError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProto {
    Tcp,
    Udp,
    Icmp,
}

/// Extracted L3/L4 packet flow metadata.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub proto: TransportProto,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

/// State tracking entry in the virtual NAT routing table.
#[derive(Debug, Clone)]
pub struct NatSession {
    pub flow: FlowKey,
    pub last_active: Instant,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub is_dns: bool,
}

/// UDP Gateway (udpgw) wire frame representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpGwFrame {
    pub flags: u8,
    pub remote_addr: SocketAddr,
    pub payload: Vec<u8>,
}

impl UdpGwFrame {
    /// Encodes a UDP frame into BadVPN UDPGW wire format:
    /// `[flags: 1B] [ip: 4B or 16B] [port: 2B BE] [payload]`
    pub fn encode(&self) -> Vec<u8> {
        let is_v6 = self.remote_addr.is_ipv6();
        let ip_len = if is_v6 { 16 } else { 4 };
        let mut out = Vec::with_capacity(1 + ip_len + 2 + self.payload.len());

        let mut flags = self.flags;
        if is_v6 {
            flags |= UDPGW_CLIENT_FLAG_IPV6;
        }
        out.push(flags);

        match self.remote_addr.ip() {
            IpAddr::V4(v4) => out.extend_from_slice(&v4.octets()),
            IpAddr::V6(v6) => out.extend_from_slice(&v6.octets()),
        }

        out.extend_from_slice(&self.remote_addr.port().to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parses a BadVPN UDPGW wire frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Tun2SocksError> {
        if buf.is_empty() {
            return Err(Tun2SocksError::PacketTooShort);
        }

        let flags = buf[0];
        let is_v6 = (flags & UDPGW_CLIENT_FLAG_IPV6) != 0;
        let ip_len = if is_v6 { 16 } else { 4 };

        if buf.len() < 1 + ip_len + 2 {
            return Err(Tun2SocksError::PacketTooShort);
        }

        let remote_ip = if is_v6 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            IpAddr::V6(Ipv6Addr::from(octets))
        } else {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&buf[1..5]);
            IpAddr::V4(Ipv4Addr::from(octets))
        };

        let port_offset = 1 + ip_len;
        let port = u16::from_be_bytes([buf[port_offset], buf[port_offset + 1]]);
        let payload = buf[port_offset + 2..].to_vec();

        Ok(Self {
            flags,
            remote_addr: SocketAddr::new(remote_ip, port),
            payload,
        })
    }
}

/// Tun2Socks Virtual Router for packet classification and flow dispatching.
pub struct Tun2SocksRouter {
    sessions: HashMap<FlowKey, NatSession>,
    idle_timeout: Duration,
    transparent_dns_enabled: bool,
    dns_redirect_target: Option<SocketAddr>,
}

impl Tun2SocksRouter {
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            idle_timeout,
            transparent_dns_enabled: true,
            dns_redirect_target: None,
        }
    }

    pub fn set_dns_redirect(&mut self, target: Option<SocketAddr>) {
        self.dns_redirect_target = target;
    }

    /// Dissects raw IP packet header to determine flow key.
    pub fn parse_flow(packet: &[u8]) -> Result<FlowKey, Tun2SocksError> {
        if packet.is_empty() {
            return Err(Tun2SocksError::PacketTooShort);
        }

        let version = packet[0] >> 4;
        match version {
            4 => Self::parse_ipv4_flow(packet),
            6 => Self::parse_ipv6_flow(packet),
            other => Err(Tun2SocksError::InvalidIpVersion(other)),
        }
    }

    fn parse_ipv4_flow(packet: &[u8]) -> Result<FlowKey, Tun2SocksError> {
        if packet.len() < 20 {
            return Err(Tun2SocksError::PacketTooShort);
        }
        let ihl = ((packet[0] & 0x0F) as usize) * 4;
        if packet.len() < ihl {
            return Err(Tun2SocksError::PacketTooShort);
        }

        let proto_num = packet[9];
        let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

        let (proto, src_port, dst_port) = match proto_num {
            6 => {
                // TCP
                if packet.len() < ihl + 4 {
                    return Err(Tun2SocksError::PacketTooShort);
                }
                let sport = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
                let dport = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
                (TransportProto::Tcp, sport, dport)
            }
            17 => {
                // UDP
                if packet.len() < ihl + 4 {
                    return Err(Tun2SocksError::PacketTooShort);
                }
                let sport = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
                let dport = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
                (TransportProto::Udp, sport, dport)
            }
            1 => (TransportProto::Icmp, 0, 0),
            other => return Err(Tun2SocksError::UnsupportedProtocol(other)),
        };

        Ok(FlowKey {
            proto,
            src: SocketAddr::new(IpAddr::V4(src_ip), src_port),
            dst: SocketAddr::new(IpAddr::V4(dst_ip), dst_port),
        })
    }

    fn parse_ipv6_flow(packet: &[u8]) -> Result<FlowKey, Tun2SocksError> {
        if packet.len() < 40 {
            return Err(Tun2SocksError::PacketTooShort);
        }
        let next_hdr = packet[6];
        let mut src_octets = [0u8; 16];
        src_octets.copy_from_slice(&packet[8..24]);
        let mut dst_octets = [0u8; 16];
        dst_octets.copy_from_slice(&packet[24..40]);

        let src_ip = Ipv6Addr::from(src_octets);
        let dst_ip = Ipv6Addr::from(dst_octets);

        let (proto, src_port, dst_port) = match next_hdr {
            6 => {
                // TCP
                if packet.len() < 44 {
                    return Err(Tun2SocksError::PacketTooShort);
                }
                let sport = u16::from_be_bytes([packet[40], packet[41]]);
                let dport = u16::from_be_bytes([packet[42], packet[43]]);
                (TransportProto::Tcp, sport, dport)
            }
            17 => {
                // UDP
                if packet.len() < 44 {
                    return Err(Tun2SocksError::PacketTooShort);
                }
                let sport = u16::from_be_bytes([packet[40], packet[41]]);
                let dport = u16::from_be_bytes([packet[42], packet[43]]);
                (TransportProto::Udp, sport, dport)
            }
            58 => (TransportProto::Icmp, 0, 0),
            other => return Err(Tun2SocksError::UnsupportedProtocol(other)),
        };

        Ok(FlowKey {
            proto,
            src: SocketAddr::new(IpAddr::V6(src_ip), src_port),
            dst: SocketAddr::new(IpAddr::V6(dst_ip), dst_port),
        })
    }

    /// Ingests a packet, updating NAT table and checking for DNS redirection.
    pub fn process_egress(&mut self, packet: &[u8]) -> Result<(FlowKey, bool), Tun2SocksError> {
        let flow = Self::parse_flow(packet)?;
        let is_dns = flow.proto == TransportProto::Udp && flow.dst.port() == 53;

        let entry = self.sessions.entry(flow.clone()).or_insert_with(|| NatSession {
            flow: flow.clone(),
            last_active: Instant::now(),
            bytes_tx: 0,
            bytes_rx: 0,
            is_dns,
        });

        entry.last_active = Instant::now();
        entry.bytes_tx += packet.len() as u64;

        Ok((flow, is_dns && self.transparent_dns_enabled))
    }

    /// Prunes expired sessions from the NAT tracking table.
    pub fn prune_idle(&mut self) -> usize {
        let now = Instant::now();
        let timeout = self.idle_timeout;
        let before_count = self.sessions.len();
        self.sessions.retain(|_, s| now.duration_since(s.last_active) < timeout);
        before_count - self.sessions.len()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udpgw_frame_roundtrip_v4() {
        let frame = UdpGwFrame {
            flags: 0,
            remote_addr: "198.51.100.1:53".parse().unwrap(),
            payload: vec![1, 2, 3, 4, 5],
        };

        let encoded = frame.encode();
        let decoded = UdpGwFrame::decode(&encoded).expect("decode failed");

        assert_eq!(frame, decoded);
        assert_eq!(decoded.remote_addr.port(), 53);
    }

    #[test]
    fn test_udpgw_frame_roundtrip_v6() {
        let frame = UdpGwFrame {
            flags: UDPGW_CLIENT_FLAG_IPV6,
            remote_addr: "[2001:db8::1]:8080".parse().unwrap(),
            payload: b"hello-udpgw-v6".to_vec(),
        };

        let encoded = frame.encode();
        assert_ne!(encoded[0] & UDPGW_CLIENT_FLAG_IPV6, 0);

        let decoded = UdpGwFrame::decode(&encoded).expect("decode failed");
        assert_eq!(frame, decoded);
    }

    #[test]
    fn test_parse_ipv4_udp_dns() {
        // Minimal IPv4 UDP DNS query packet (header: 20B IPv4 + 8B UDP)
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45; // IPv4, IHL=5
        pkt[9] = 17;   // UDP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]); // src
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);   // dst
        pkt[20..22].copy_from_slice(&54321u16.to_be_bytes()); // src port
        pkt[22..24].copy_from_slice(&53u16.to_be_bytes());    // dst port 53 (DNS)
        pkt[24..26].copy_from_slice(&8u16.to_be_bytes());     // udp length

        let flow = Tun2SocksRouter::parse_flow(&pkt).expect("parse flow");
        assert_eq!(flow.proto, TransportProto::Udp);
        assert_eq!(flow.src.port(), 54321);
        assert_eq!(flow.dst.port(), 53);

        let mut router = Tun2SocksRouter::new(Duration::from_secs(30));
        let (res_flow, is_dns) = router.process_egress(&pkt).expect("process");
        assert_eq!(res_flow, flow);
        assert!(is_dns);
        assert_eq!(router.session_count(), 1);
    }

    #[test]
    fn test_prune_idle_sessions() {
        let mut router = Tun2SocksRouter::new(Duration::from_millis(10));
        let flow = FlowKey {
            proto: TransportProto::Tcp,
            src: "10.0.0.2:1234".parse().unwrap(),
            dst: "93.184.216.34:80".parse().unwrap(),
        };

        router.sessions.insert(flow.clone(), NatSession {
            flow,
            last_active: Instant::now() - Duration::from_millis(50),
            bytes_tx: 100,
            bytes_rx: 200,
            is_dns: false,
        });

        assert_eq!(router.session_count(), 1);
        let pruned = router.prune_idle();
        assert_eq!(pruned, 1);
        assert_eq!(router.session_count(), 0);
    }
}
