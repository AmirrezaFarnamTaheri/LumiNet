//! Relay Access Control List (ACL) Filter & UDP-over-TCP Multiplexer.
//!
//! Ported and unified from `bepass-relay-main`.
//! Provides:
//!   - Edge Source Whitelist: Filters ingress traffic to authorized Cloudflare edge IP CIDR ranges.
//!   - Abusive / Torrent Tracker Blacklist: Rejects egress forwarding to local and torrent tracker destinations.
//!   - UDP-over-TCP Session Multiplexer: 8-byte session/stream header framing and 2-byte tag response routing.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use serde::{Deserialize, Serialize};

/// IP CIDR prefix representation for subnet evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayCidr {
    V4 { addr: Ipv4Addr, prefix: u8 },
    V6 { addr: Ipv6Addr, prefix: u8 },
}

impl RelayCidr {
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.trim().split('/').collect();
        if parts.len() != 2 {
            return None;
        }
        let prefix: u8 = parts[1].parse().ok()?;
        if let Ok(ipv4) = parts[0].parse::<Ipv4Addr>() {
            if prefix <= 32 {
                return Some(RelayCidr::V4 { addr: ipv4, prefix });
            }
        } else if let Ok(ipv6) = parts[0].parse::<Ipv6Addr>() {
            if prefix <= 128 {
                return Some(RelayCidr::V6 { addr: ipv6, prefix });
            }
        }
        None
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (RelayCidr::V4 { addr, prefix }, IpAddr::V4(target)) => {
                if *prefix == 0 {
                    return true;
                }
                if *prefix > 32 {
                    return false;
                }
                let mask = if *prefix == 32 {
                    u32::MAX
                } else {
                    !((1u32 << (32 - *prefix)) - 1)
                };
                (u32::from_be_bytes(addr.octets()) & mask) == (u32::from_be_bytes(target.octets()) & mask)
            }
            (RelayCidr::V6 { addr, prefix }, IpAddr::V6(target)) => {
                if *prefix == 0 {
                    return true;
                }
                if *prefix > 128 {
                    return false;
                }
                let mask = if *prefix == 128 {
                    u128::MAX
                } else {
                    !((1u128 << (128 - *prefix)) - 1)
                };
                (u128::from_be_bytes(addr.octets()) & mask) == (u128::from_be_bytes(target.octets()) & mask)
            }
            _ => false,
        }
    }
}

/// Standard Cloudflare Edge IP CIDRs permitted for ingress relay.
pub const DEFAULT_EDGE_CIDRS: &[&str] = &[
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/12",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "2400:cb00::/32",
    "2405:8100::/32",
    "2405:b500::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2c0f:f248::/32",
    "2a06:98c0::/29",
];

/// Known abusive, localhost, and torrent tracker CIDRs blocked from egress relay.
pub const DEFAULT_BLOCKED_CIDRS: &[&str] = &[
    "127.0.0.0/8",
    "::1/128",
    "93.158.213.92/32",
    "102.223.180.235/32",
    "23.134.88.6/32",
    "185.243.218.213/32",
    "208.83.20.20/32",
    "91.216.110.52/32",
    "83.146.97.90/32",
    "23.157.120.14/32",
    "185.102.219.163/32",
    "163.172.29.130/32",
    "156.234.201.18/32",
    "209.141.59.16/32",
    "34.94.213.23/32",
    "192.3.165.191/32",
    "130.61.55.93/32",
    "109.201.134.183/32",
    "95.31.11.224/32",
    "83.102.180.21/32",
    "192.95.46.115/32",
    "198.100.149.66/32",
    "95.216.74.39/32",
    "51.68.174.87/32",
    "37.187.111.136/32",
    "51.15.79.209/32",
    "45.92.156.182/32",
    "49.12.76.8/32",
    "5.196.89.204/32",
    "62.233.57.13/32",
    "45.9.60.30/32",
    "35.227.12.84/32",
    "179.43.155.30/32",
    "94.243.222.100/32",
    "207.241.231.226/32",
    "207.241.226.111/32",
    "51.159.54.68/32",
    "82.65.115.10/32",
    "95.217.167.10/32",
    "86.57.161.157/32",
    "83.31.30.230/32",
    "94.103.87.87/32",
    "160.119.252.41/32",
    "193.42.111.57/32",
    "80.240.22.46/32",
    "107.189.31.134/32",
    "104.244.79.114/32",
    "85.239.33.28/32",
    "61.222.178.254/32",
    "38.7.201.142/32",
    "51.81.222.188/32",
    "103.196.36.31/32",
    "23.153.248.2/32",
    "73.170.204.100/32",
    "176.31.250.174/32",
    "149.56.179.233/32",
    "212.237.53.230/32",
    "185.68.21.244/32",
    "82.156.24.219/32",
    "216.201.9.155/32",
    "51.15.41.46/32",
    "85.206.172.159/32",
    "104.244.77.87/32",
    "37.27.4.53/32",
    "192.3.165.198/32",
    "15.204.205.14/32",
    "103.122.21.50/32",
    "104.131.98.232/32",
    "173.249.201.201/32",
    "23.254.228.89/32",
    "5.102.159.190/32",
    "65.130.205.148/32",
    "119.28.71.45/32",
    "159.69.65.157/32",
    "160.251.78.190/32",
    "107.189.7.143/32",
    "159.65.224.91/32",
    "185.217.199.21/32",
    "91.224.92.110/32",
    "161.97.67.210/32",
    "51.15.3.74/32",
    "209.126.11.233/32",
    "37.187.95.112/32",
    "167.99.185.219/32",
    "144.91.88.22/32",
    "88.99.2.212/32",
    "37.59.48.81/32",
    "95.179.130.187/32",
    "51.15.26.25/32",
    "192.9.228.30/32",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayAclVerdict {
    Allowed,
    SourceNotAllowed(IpAddr),
    DestinationBlocked(IpAddr),
}

/// Relay ACL Firewall holding source whitelist and destination blacklist trees.
#[derive(Debug, Clone)]
pub struct RelayAclFilter {
    source_whitelist: Vec<RelayCidr>,
    destination_blacklist: Vec<RelayCidr>,
}

impl Default for RelayAclFilter {
    fn default() -> Self {
        Self::new_default()
    }
}

impl RelayAclFilter {
    /// Initializes the filter with canonical Cloudflare edge whitelist and tracker blacklist.
    pub fn new_default() -> Self {
        let mut filter = Self {
            source_whitelist: Vec::new(),
            destination_blacklist: Vec::new(),
        };

        for cidr_str in DEFAULT_EDGE_CIDRS {
            if let Some(cidr) = RelayCidr::parse(cidr_str) {
                filter.source_whitelist.push(cidr);
            }
        }

        for cidr_str in DEFAULT_BLOCKED_CIDRS {
            if let Some(cidr) = RelayCidr::parse(cidr_str) {
                filter.destination_blacklist.push(cidr);
            }
        }

        filter
    }

    pub fn add_source_whitelist(&mut self, cidr: RelayCidr) {
        self.source_whitelist.push(cidr);
    }

    pub fn add_destination_blacklist(&mut self, cidr: RelayCidr) {
        self.destination_blacklist.push(cidr);
    }

    pub fn is_source_allowed(&self, addr: &IpAddr) -> bool {
        self.source_whitelist.iter().any(|cidr| cidr.contains(addr))
    }

    pub fn is_destination_allowed(&self, addr: &IpAddr) -> bool {
        !self.destination_blacklist.iter().any(|cidr| cidr.contains(addr))
    }

    pub fn evaluate(&self, src: &IpAddr, dst: &IpAddr) -> RelayAclVerdict {
        if !self.is_source_allowed(src) {
            return RelayAclVerdict::SourceNotAllowed(*src);
        }
        if !self.is_destination_allowed(dst) {
            return RelayAclVerdict::DestinationBlocked(*dst);
        }
        RelayAclVerdict::Allowed
    }
}

/// UDP-over-TCP sub-packet frame.
/// Format: `[6-byte session ID][2-byte stream tag][payload]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpOverTcpFrame {
    pub session_id: [u8; 6],
    pub stream_tag: [u8; 2],
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpMuxError {
    BufferTooShort,
}

impl std::fmt::Display for UdpMuxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferTooShort => write!(f, "buffer too short for UDP-over-TCP header (minimum 8 bytes required)"),
        }
    }
}

impl std::error::Error for UdpMuxError {}

impl UdpOverTcpFrame {
    pub fn new(session_id: [u8; 6], stream_tag: [u8; 2], payload: Vec<u8>) -> Self {
        Self {
            session_id,
            stream_tag,
            payload,
        }
    }

    /// Encodes request frame: 8-byte header + payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.payload.len());
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.stream_tag);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decodes request frame from stream buffer.
    pub fn decode(src: &[u8]) -> Result<Self, UdpMuxError> {
        if src.len() < 8 {
            return Err(UdpMuxError::BufferTooShort);
        }
        let mut session_id = [0u8; 6];
        session_id.copy_from_slice(&src[0..6]);
        let mut stream_tag = [0u8; 2];
        stream_tag.copy_from_slice(&src[6..8]);
        let payload = src[8..].to_vec();

        Ok(Self {
            session_id,
            stream_tag,
            payload,
        })
    }

    /// Builds a response datagram packet back to the client over TCP.
    /// In `bepass-relay`, response packets are framed with the 2-byte `stream_tag` (`header[6:]`).
    pub fn build_response(stream_tag: [u8; 2], datagram: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + datagram.len());
        out.extend_from_slice(&stream_tag);
        out.extend_from_slice(datagram);
        out
    }

    /// Decodes a response datagram arriving from the relay over TCP.
    pub fn decode_response(src: &[u8]) -> Result<([u8; 2], &[u8]), UdpMuxError> {
        if src.len() < 2 {
            return Err(UdpMuxError::BufferTooShort);
        }
        let mut stream_tag = [0u8; 2];
        stream_tag.copy_from_slice(&src[0..2]);
        Ok((stream_tag, &src[2..]))
    }

    /// Computes unique channel multiplexing key: `<destination>:<hex_header>`.
    pub fn channel_key(destination: &str, session_id: &[u8; 6], stream_tag: &[u8; 2]) -> String {
        let hex_session = session_id.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        let hex_tag = stream_tag.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        format!("{}:{}{}", destination, hex_session, hex_tag)
    }
}
