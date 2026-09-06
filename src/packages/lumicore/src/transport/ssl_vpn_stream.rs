//! # SSL-VPN Ethernet-over-HTTPS Frame Codec & Virtual NAT
//!
//! Encapsulates raw Ethernet frames into HTTPS streaming chunks and maintains
//! a high-performance 5-tuple Virtual NAT translation table.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

pub const SSL_VPN_FRAME_DATA: u8 = 0x00;
pub const SSL_VPN_FRAME_KEEPALIVE: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SslVpnFrame {
    pub frame_type: u8,
    pub ethernet_payload: Vec<u8>,
}

impl SslVpnFrame {
    pub fn new_data(payload: Vec<u8>) -> Self {
        Self {
            frame_type: SSL_VPN_FRAME_DATA,
            ethernet_payload: payload,
        }
    }

    pub fn new_keepalive() -> Self {
        Self {
            frame_type: SSL_VPN_FRAME_KEEPALIVE,
            ethernet_payload: Vec::new(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let len = (self.ethernet_payload.len() + 1) as u16;
        let mut buf = Vec::with_capacity(2 + len as usize);
        buf.extend_from_slice(&len.to_be_bytes());
        buf.push(self.frame_type);
        buf.extend_from_slice(&self.ethernet_payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Result<(Self, usize), &'static str> {
        if bytes.len() < 3 {
            return Err("Buffer too short for SSL-VPN frame header");
        }
        let mut len_b = [0u8; 2];
        len_b.copy_from_slice(&bytes[0..2]);
        let total_len = u16::from_be_bytes(len_b) as usize;

        if bytes.len() < 2 + total_len {
            return Err("Incomplete SSL-VPN frame payload");
        }

        let frame_type = bytes[2];
        let ethernet_payload = bytes[3..2 + total_len].to_vec();

        Ok((Self { frame_type, ethernet_payload }, 2 + total_len))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NatTuple {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub protocol: u8, // 6 = TCP, 17 = UDP
}

pub struct VirtualNatEntry {
    pub virtual_port: u16,
    pub last_seen: Instant,
}

pub struct VirtualNatTable {
    mappings: HashMap<NatTuple, VirtualNatEntry>,
    next_port: u16,
    tcp_timeout: Duration,
    udp_timeout: Duration,
}

impl VirtualNatTable {
    pub fn new() -> Self {
        Self {
            mappings: HashMap::new(),
            next_port: 20000,
            tcp_timeout: Duration::from_secs(1800),
            udp_timeout: Duration::from_secs(60),
        }
    }

    pub fn get_or_allocate(&mut self, tuple: &NatTuple) -> u16 {
        let now = Instant::now();
        if let Some(entry) = self.mappings.get_mut(tuple) {
            entry.last_seen = now;
            return entry.virtual_port;
        }

        let port = self.next_port;
        self.next_port = if self.next_port >= 65000 { 20000 } else { self.next_port + 1 };

        self.mappings.insert(tuple.clone(), VirtualNatEntry {
            virtual_port: port,
            last_seen: now,
        });

        port
    }

    pub fn prune_expired(&mut self) {
        let now = Instant::now();
        let tcp_t = self.tcp_timeout;
        let udp_t = self.udp_timeout;

        self.mappings.retain(|k, v| {
            let limit = if k.protocol == 6 { tcp_t } else { udp_t };
            now.duration_since(v.last_seen) < limit
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn test_ssl_vpn_frame_codec() {
        let frame = SslVpnFrame::new_data(vec![0xAA, 0xBB, 0xCC]);
        let bytes = frame.serialize();
        let (parsed, consumed) = SslVpnFrame::deserialize(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.frame_type, SSL_VPN_FRAME_DATA);
        assert_eq!(parsed.ethernet_payload, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_virtual_nat_table() {
        let mut nat = VirtualNatTable::new();
        let tuple = NatTuple {
            src: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 12345)),
            dst: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 80)),
            protocol: 6,
        };
        let p1 = nat.get_or_allocate(&tuple);
        let p2 = nat.get_or_allocate(&tuple);
        assert_eq!(p1, p2);
    }
}
