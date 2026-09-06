//! # IP Address Validation
//!
//! Unified IP validation with superset of all checks from security.rs + ip_security.rs + virtual_dns.rs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Checks if an IP address is private, loopback, link-local, or otherwise internal.
/// Superset of all checks from security.rs (10+ checks).
pub fn is_private_address(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

/// Checks if address is safe to proxy to (NOT private).
pub fn is_safe_target(addr: &IpAddr) -> bool {
    !is_private_address(addr)
}

/// Checks if IP is a virtual/fake DNS IP (198.18.0.0/15).
/// From virtual_dns.rs.
pub fn is_virtual_ip(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)
        }
        _ => false,
    }
}

fn is_private_v4(ip: &Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_private()
        || ip.is_link_local()
        || is_shared_address_v4(ip)
        || is_benchmarking_v4(ip)
        || is_documentation_v4(ip)
        || ip.is_broadcast()
        || is_reserved_v4(ip)
}

fn is_private_v6(ip: &Ipv6Addr) -> bool {
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || is_unique_local_v6(ip)
        || ip.is_unicast_link_local()
        || is_documentation_v6(ip)
}

fn is_shared_address_v4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

fn is_benchmarking_v4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 198 && (o[1] == 18 || o[1] == 19)
}

fn is_documentation_v4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
}

fn is_unique_local_v6(ip: &Ipv6Addr) -> bool {
    let o = ip.octets();
    (o[0] & 0xFE) == 0xFC
}

fn is_documentation_v6(ip: &Ipv6Addr) -> bool {
    let o = ip.octets();
    o[0] == 0x20 && o[1] == 0x01 && o[2] == 0x0D && o[3] == 0xB8
}

fn is_reserved_v4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 0 || (o[0] == 192 && o[1] == 0 && o[2] == 0) || (o[0] & 0xF0) == 240
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_v4() {
        assert!(is_private_address(&"127.0.0.1".parse().unwrap()));
        assert!(is_private_address(&"10.0.0.1".parse().unwrap()));
        assert!(is_private_address(&"172.16.0.1".parse().unwrap()));
        assert!(is_private_address(&"192.168.1.1".parse().unwrap()));
        assert!(is_private_address(&"169.254.1.1".parse().unwrap()));
        assert!(is_private_address(&"100.64.0.1".parse().unwrap()));
        assert!(is_private_address(&"198.18.0.1".parse().unwrap()));
    }

    #[test]
    fn test_public_v4() {
        assert!(!is_private_address(&"8.8.8.8".parse().unwrap()));
        assert!(!is_private_address(&"1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn test_virtual_ip() {
        assert!(is_virtual_ip(&"198.18.0.1".parse().unwrap()));
        assert!(!is_virtual_ip(&"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_safe_target() {
        assert!(is_safe_target(&"8.8.8.8".parse().unwrap()));
        assert!(!is_safe_target(&"10.0.0.1".parse().unwrap()));
    }
}
