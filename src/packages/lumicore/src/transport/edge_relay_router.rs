//! Edge Serverless Relay Router & Cloudflare Loopback Evasion Engine.
//!
//! Ported and unified from `bepass-worker-main`.
//! Provides:
//!   - Serverless WebSocket tunnel dispatch and session-hashed relay node selection.
//!   - Cloudflare loopback detection (diverts CF edge target IPs to upstream relays to prevent 1000/1001 errors).
//!   - Mandatory UDP diversion over TCP stream relay.
//!   - Quiet connection retry fallback routing.
//!   - RFC 8484 wire-format DNS A-record query crafting for upstream edge DoH lookups.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use serde::{Deserialize, Serialize};

/// Target transport protocol for edge routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayNetwork {
    Tcp,
    Udp,
}

impl RelayNetwork {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// CIDR prefix structure for edge IP range checking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeCidr {
    V4 { addr: Ipv4Addr, prefix: u8 },
    V6 { addr: Ipv6Addr, prefix: u8 },
}

impl EdgeCidr {
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.trim().split('/').collect();
        if parts.len() != 2 {
            return None;
        }
        let prefix: u8 = parts[1].parse().ok()?;
        if let Ok(v4) = parts[0].parse::<Ipv4Addr>() {
            if prefix <= 32 {
                return Some(EdgeCidr::V4 { addr: v4, prefix });
            }
        } else if let Ok(v6) = parts[0].parse::<Ipv6Addr>() {
            if prefix <= 128 {
                return Some(EdgeCidr::V6 { addr: v6, prefix });
            }
        }
        None
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (EdgeCidr::V4 { addr, prefix }, IpAddr::V4(target)) => {
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
            (EdgeCidr::V6 { addr, prefix }, IpAddr::V6(target)) => {
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

/// Canonical Cloudflare IPv4 & IPv6 CIDRs used to detect and evade loopback restrictions.
pub const CANONICAL_CF_IPV4: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
];

pub const CANONICAL_CF_IPV6: &[&str] = &[
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

/// Configuration for the edge relay router.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeRelayConfig {
    pub relay_hosts: Vec<String>,
    pub relay_port: u16,
    pub dns_host: String,
    pub cloudflare_cidrs: Vec<EdgeCidr>,
}

impl Default for EdgeRelayConfig {
    fn default() -> Self {
        let mut cidrs = Vec::new();
        for s in CANONICAL_CF_IPV4 {
            if let Some(c) = EdgeCidr::parse(s) {
                cidrs.push(c);
            }
        }
        for s in CANONICAL_CF_IPV6 {
            if let Some(c) = EdgeCidr::parse(s) {
                cidrs.push(c);
            }
        }

        Self {
            relay_hosts: vec![
                "relay1.bepass.org".to_string(),
                "relay2.bepass.org".to_string(),
                "relay3.bepass.org".to_string(),
            ],
            relay_port: 6666,
            dns_host: "1.1.1.1".to_string(),
            cloudflare_cidrs: cidrs,
        }
    }
}

/// Outbound target request parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteTarget {
    pub network: RelayNetwork,
    pub host: String,
    pub port: u16,
    pub resolved_ip: Option<IpAddr>,
}

/// The decision produced by the EdgeRelayRouter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeRoutingDecision {
    /// Outbound can dial the target directly without intermediate relay overhead.
    Direct {
        host: String,
        port: u16,
    },
    /// Outbound must route through the relay pool with prepended delimiter header (`<net>@<host>$<port>\r\n`).
    RelayChained {
        relay_host: String,
        relay_port: u16,
        delimiter_header: String,
    },
}

/// Edge Serverless Relay Router.
#[derive(Debug, Clone)]
pub struct EdgeRelayRouter {
    config: EdgeRelayConfig,
}

impl Default for EdgeRelayRouter {
    fn default() -> Self {
        Self::new(EdgeRelayConfig::default())
    }
}

impl EdgeRelayRouter {
    pub fn new(config: EdgeRelayConfig) -> Self {
        Self { config }
    }

    /// Selects an upstream relay node using deterministic session ID modulo or first node.
    pub fn select_relay_endpoint(&self, session_id: Option<u64>) -> (String, u16) {
        if self.config.relay_hosts.is_empty() {
            return ("127.0.0.1".to_string(), self.config.relay_port);
        }

        let idx = match session_id {
            Some(sid) => (sid as usize) % self.config.relay_hosts.len(),
            None => 0,
        };

        (self.config.relay_hosts[idx].clone(), self.config.relay_port)
    }

    /// Checks whether an IP address belongs to the Cloudflare network range.
    pub fn is_cloudflare_ip(&self, ip: &IpAddr) -> bool {
        self.config.cloudflare_cidrs.iter().any(|c| c.contains(ip))
    }

    /// Evaluates routing policy for the destination target:
    /// 1. UDP is always redirected to relay (Cloudflare Worker sockets cannot do direct raw UDP).
    /// 2. Targets resolving to Cloudflare edge IPs are redirected to relay to prevent edge loopback blocks.
    /// 3. Normal public targets are routed directly.
    pub fn decide_route(&self, target: &RouteTarget, session_id: Option<u64>) -> EdgeRoutingDecision {
        let requires_relay = target.network == RelayNetwork::Udp
            || target.resolved_ip.as_ref().map_or(false, |ip| self.is_cloudflare_ip(ip));

        if requires_relay {
            let (relay_host, relay_port) = self.select_relay_endpoint(session_id);
            let header = format!("{}@{}${}\r\n", target.network.as_str(), target.host, target.port);
            EdgeRoutingDecision::RelayChained {
                relay_host,
                relay_port,
                delimiter_header: header,
            }
        } else {
            EdgeRoutingDecision::Direct {
                host: target.host.clone(),
                port: target.port,
            }
        }
    }

    /// Builds a fallback relay route when a direct connection fails or yields no incoming traffic.
    pub fn build_fallback_relay_route(
        &self,
        target: &RouteTarget,
        session_id: Option<u64>,
    ) -> EdgeRoutingDecision {
        let (relay_host, relay_port) = self.select_relay_endpoint(session_id);
        let header = format!("{}@{}${}\r\n", target.network.as_str(), target.host, target.port);
        EdgeRoutingDecision::RelayChained {
            relay_host,
            relay_port,
            delimiter_header: header,
        }
    }

    /// Synthesizes an RFC 8484 / RFC 1035 wire DNS query for domain A-record resolution.
    /// Byte layout:
    /// - Transaction ID: 0x1234
    /// - Flags: 0x0100 (Standard query, Recursion Desired)
    /// - Questions: 1, Answer RRs: 0, Authority RRs: 0, Additional RRs: 0
    /// - QNAME: Length-prefixed labels followed by 0x00
    /// - QTYPE: 0x0001 (Type A)
    /// - QCLASS: 0x0001 (Class IN)
    pub fn build_doh_a_query(domain: &str) -> Vec<u8> {
        let mut query = Vec::with_capacity(12 + domain.len() + 6);

        // Header
        query.extend_from_slice(&[
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
        ]);

        // QNAME
        for part in domain.split('.') {
            if part.is_empty() {
                continue;
            }
            let bytes = part.as_bytes();
            query.push(bytes.len() as u8);
            query.extend_from_slice(bytes);
        }
        query.push(0x00); // Null terminator

        // QTYPE & QCLASS
        query.extend_from_slice(&[
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ]);

        query
    }
}
