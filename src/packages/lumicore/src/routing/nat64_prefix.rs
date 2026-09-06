//! RFC 6052 NAT64 IPv4-to-IPv6 Prefix Synthesizer and Dynamic Fallback Router.
//!
//! Provides algorithmic mapping between IPv4 addresses and IPv6 prefixes:
//! 1. RFC 6052 / NAT64 IPv4 embedding: Encodes IPv4 octets into the trailing 32 bits of a /96 prefix.
//!    Supports both standard Well-Known Prefix (`64:ff9b::/96`) and custom Cloudflare/carrier prefixes.
//! 2. Dual-mode fallback router:
//!    - `ProxyIp`: Retries failed direct outbound attempts by selecting from a healthy proxy IP pool.
//!    - `DynamicPrefix`: Resolves target IPv4 and synthesizes a NAT64 IPv6 address, allowing edge workers
//!      and clients to bypass IPv4 outbound blocks or reach IPv6 translators directly.
//! 3. Two-way transformation: Synthesizes `Ipv6Addr` from `Ipv4Addr` and decodes the embedded IPv4 from NAT64.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Standard RFC 6052 Well-Known Prefix: 64:ff9b::/96
pub const RFC6052_WELL_KNOWN_PREFIX: Ipv6Addr =
    Ipv6Addr::new(0x0064, 0xff9b, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000);

/// Outbound routing strategy when direct egress fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackMode {
    ProxyIp,
    DynamicPrefix,
}

/// Dynamic NAT64 Prefix Synthesizer and Router.
#[derive(Debug, Clone)]
pub struct Nat64Router {
    pub mode: FallbackMode,
    pub prefix: Ipv6Addr,
    pub proxy_ips: Vec<String>,
}

impl Default for Nat64Router {
    fn default() -> Self {
        Self {
            mode: FallbackMode::DynamicPrefix,
            prefix: RFC6052_WELL_KNOWN_PREFIX,
            proxy_ips: Vec::new(),
        }
    }
}

impl Nat64Router {
    pub fn new(mode: FallbackMode, prefix: Ipv6Addr, proxy_ips: Vec<String>) -> Self {
        Self {
            mode,
            prefix,
            proxy_ips,
        }
    }

    /// Synthesizes an IPv6 address embedding the target IPv4 into the configured /96 prefix.
    pub fn synthesize(&self, ipv4: Ipv4Addr) -> Ipv6Addr {
        synthesize_nat64(ipv4, &self.prefix)
    }

    /// Selects an outbound target given a destination IPv4.
    pub fn route_outbound(&self, destination_v4: Ipv4Addr) -> OutboundRoute {
        match self.mode {
            FallbackMode::DynamicPrefix => {
                let v6 = self.synthesize(destination_v4);
                OutboundRoute::SynthesizedIpv6(v6)
            }
            FallbackMode::ProxyIp => {
                if let Some(proxy) = self.proxy_ips.first() {
                    OutboundRoute::ProxyHop(proxy.clone())
                } else {
                    OutboundRoute::Direct(destination_v4)
                }
            }
        }
    }
}

/// Result of outbound fallback route evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundRoute {
    Direct(Ipv4Addr),
    SynthesizedIpv6(Ipv6Addr),
    ProxyHop(String),
}

/// Embeds an IPv4 address into the lower 32 bits of an IPv6 /96 prefix (RFC 6052 §2.2).
pub fn synthesize_nat64(ipv4: Ipv4Addr, prefix: &Ipv6Addr) -> Ipv6Addr {
    let prefix_segments = prefix.segments();
    let octets = ipv4.octets();
    let high = ((octets[0] as u16) << 8) | (octets[1] as u16);
    let low = ((octets[2] as u16) << 8) | (octets[3] as u16);

    Ipv6Addr::new(
        prefix_segments[0],
        prefix_segments[1],
        prefix_segments[2],
        prefix_segments[3],
        prefix_segments[4],
        prefix_segments[5],
        high,
        low,
    )
}

/// Extracts embedded IPv4 address from an RFC 6052 /96 synthesized IPv6 address.
pub fn extract_nat64(synthesized: &Ipv6Addr, prefix: &Ipv6Addr) -> Option<Ipv4Addr> {
    let syn_segs = synthesized.segments();
    let pfx_segs = prefix.segments();

    // Verify first 96 bits (6 segments of 16 bits) match the prefix
    for i in 0..6 {
        if syn_segs[i] != pfx_segs[i] {
            return None;
        }
    }

    let high = syn_segs[6];
    let low = syn_segs[7];

    Some(Ipv4Addr::new(
        (high >> 8) as u8,
        (high & 0xff) as u8,
        (low >> 8) as u8,
        (low & 0xff) as u8,
    ))
}

/// Formats a synthesized IPv6 address in bracketed URI notation, e.g. `[64:ff9b::198.51.100.1]`.
pub fn format_bracketed_ipv6(addr: &Ipv6Addr) -> String {
    format!("[{addr}]")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc6052_well_known_prefix_synthesis() {
        let v4 = Ipv4Addr::new(192, 0, 2, 33);
        let v6 = synthesize_nat64(v4, &RFC6052_WELL_KNOWN_PREFIX);

        // 192.0 -> 0xc000, 2.33 -> 0x0221
        assert_eq!(
            v6,
            Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0xc000, 0x0221)
        );

        let recovered = extract_nat64(&v6, &RFC6052_WELL_KNOWN_PREFIX);
        assert_eq!(recovered, Some(v4));
    }

    #[test]
    fn test_custom_prefix_synthesis() {
        // e.g. Cloudflare WARP carrier prefix 2606:4700::/96
        let carrier_prefix: Ipv6Addr = "2606:4700::".parse().unwrap();
        let v4 = Ipv4Addr::new(1, 1, 1, 1);
        let v6 = synthesize_nat64(v4, &carrier_prefix);

        // 1.1 -> 0x0101, 1.1 -> 0x0101
        assert_eq!(
            v6,
            Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0x0101, 0x0101)
        );

        let recovered = extract_nat64(&v6, &carrier_prefix);
        assert_eq!(recovered, Some(v4));
    }

    #[test]
    fn test_router_modes() {
        let router_prefix = Nat64Router::default();
        let target = Ipv4Addr::new(8, 8, 8, 8);

        let route = router_prefix.route_outbound(target);
        match route {
            OutboundRoute::SynthesizedIpv6(v6) => {
                assert_eq!(v6.segments()[6], 0x0808);
                assert_eq!(v6.segments()[7], 0x0808);
            }
            _ => panic!("Expected SynthesizedIpv6"),
        }

        let router_proxy = Nat64Router::new(
            FallbackMode::ProxyIp,
            RFC6052_WELL_KNOWN_PREFIX,
            vec!["104.28.1.1:443".to_string()],
        );
        let route2 = router_proxy.route_outbound(target);
        assert_eq!(route2, OutboundRoute::ProxyHop("104.28.1.1:443".to_string()));
    }
}
