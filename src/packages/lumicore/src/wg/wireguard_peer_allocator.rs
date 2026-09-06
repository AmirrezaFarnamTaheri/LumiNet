//! # Dynamic WireGuard IPAM & Peer Config Synthesizer
//!
//! Allocates next-available client IP addresses in IPv4 and IPv6 subnets,
//! generates client configuration blocks, and parses WireGuard status dumps.

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

pub struct WireguardCidrAllocator {
    ipv4_base: [u8; 3], // e.g. 10.8.0
    ipv6_prefix: [u8; 12], // e.g. fdcc:ad11:1111::
    allocated_v4: HashSet<u8>, // host byte in .2 .. .254
    allocated_v6: HashSet<u16>,
}

impl WireguardCidrAllocator {
    pub fn new(ipv4_base: [u8; 3], ipv6_prefix: [u8; 12]) -> Self {
        let mut alloc = Self {
            ipv4_base,
            ipv6_prefix,
            allocated_v4: HashSet::new(),
            allocated_v6: HashSet::new(),
        };
        // Reserve .1 for gateway interface
        alloc.allocated_v4.insert(1);
        alloc.allocated_v6.insert(1);
        alloc
    }

    pub fn allocate_next_ip(&mut self) -> Result<(Ipv4Addr, Ipv6Addr), &'static str> {
        // Find next available v4 host (2..254)
        let mut v4_host = None;
        for h in 2..=254 {
            if !self.allocated_v4.contains(&h) {
                v4_host = Some(h);
                break;
            }
        }
        let h_byte = v4_host.ok_or("IPv4 CIDR exhausted")?;
        self.allocated_v4.insert(h_byte);

        // Find next available v6 host
        let mut v6_host = None;
        for h in 2..=65534 {
            if !self.allocated_v6.contains(&h) {
                v6_host = Some(h);
                break;
            }
        }
        let h_v6 = v6_host.ok_or("IPv6 CIDR exhausted")?;
        self.allocated_v6.insert(h_v6);

        let v4 = Ipv4Addr::new(self.ipv4_base[0], self.ipv4_base[1], self.ipv4_base[2], h_byte);
        let mut v6_octets = [0u8; 16];
        v6_octets[..12].copy_from_slice(&self.ipv6_prefix);
        v6_octets[14] = (h_v6 >> 8) as u8;
        v6_octets[15] = (h_v6 & 0xFF) as u8;
        let v6 = Ipv6Addr::from(v6_octets);

        Ok((v4, v6))
    }

    pub fn release_ip(&mut self, v4: &Ipv4Addr) {
        let octets = v4.octets();
        if octets[0..3] == self.ipv4_base {
            self.allocated_v4.remove(&octets[3]);
        }
    }

    pub fn format_client_conf(
        client_private_key: &str,
        client_v4: &Ipv4Addr,
        client_v6: &Ipv6Addr,
        server_public_key: &str,
        server_endpoint: &str,
        dns_server: &str,
    ) -> String {
        format!(
            "[Interface]\nPrivateKey = {}\nAddress = {}/32, {}/128\nDNS = {}\n\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
            client_private_key, client_v4, client_v6, dns_server, server_public_key, server_endpoint
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wireguard_ipam_allocation() {
        let mut alloc = WireguardCidrAllocator::new([10, 8, 0], [0xfd, 0xcc, 0xad, 0x11, 0x11, 0x11, 0, 0, 0, 0, 0, 0]);
        let (v4_1, v6_1) = alloc.allocate_next_ip().unwrap();
        assert_eq!(v4_1, Ipv4Addr::new(10, 8, 0, 2));

        let (v4_2, _) = alloc.allocate_next_ip().unwrap();
        assert_eq!(v4_2, Ipv4Addr::new(10, 8, 0, 3));

        alloc.release_ip(&v4_1);
        let (v4_realloc, _) = alloc.allocate_next_ip().unwrap();
        assert_eq!(v4_realloc, Ipv4Addr::new(10, 8, 0, 2));

        let conf = WireguardCidrAllocator::format_client_conf(
            "client_priv_key",
            &v4_2,
            &v6_1,
            "srv_pub_key",
            "vpn.example.com:51820",
            "1.1.1.1",
        );
        assert!(conf.contains("PersistentKeepalive = 25"));
        assert!(conf.contains("Address = 10.8.0.3/32"));
    }
}
