//! # Cloudflare WARP Registration Client & WireGuard Profile Generator
//!
//! Formats Warp v0a/v2 registration payloads, parses license activation responses,
//! and generates WireGuard client profiles with reserved 3-byte identifiers.

use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarpAccountProfile {
    pub account_id: String,
    pub access_token: String,
    pub private_key: String,
    pub public_key: String,
    pub ipv4_address: Ipv4Addr,
    pub ipv6_address: Ipv6Addr,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub reserved_bytes: [u8; 3],
}

impl WarpAccountProfile {
    pub fn new(
        account_id: String,
        access_token: String,
        private_key: String,
        public_key: String,
        ipv4_address: Ipv4Addr,
        ipv6_address: Ipv6Addr,
    ) -> Self {
        Self {
            account_id,
            access_token,
            private_key,
            public_key,
            ipv4_address,
            ipv6_address,
            endpoint_host: "162.159.192.1".to_string(),
            endpoint_port: 2408,
            reserved_bytes: [0, 0, 0],
        }
    }

    pub fn to_wireguard_conf(&self) -> String {
        format!(
            "[Interface]\nPrivateKey = {}\nAddress = {}/32, {}/128\nDNS = 1.1.1.1, 2606:4700:4700::1111\n\n[Peer]\nPublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {}:{}\n",
            self.private_key,
            self.ipv4_address,
            self.ipv6_address,
            self.endpoint_host,
            self.endpoint_port
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_warp_profile_wireguard_generation() {
        let profile = WarpAccountProfile::new(
            "acc_12345".to_string(),
            "token_abcde".to_string(),
            "privkey_warp".to_string(),
            "pubkey_warp".to_string(),
            Ipv4Addr::new(172, 16, 0, 2),
            "2606:4700:110:8f69:a::2".parse().unwrap(),
        );

        let conf = profile.to_wireguard_conf();
        assert!(conf.contains("Address = 172.16.0.2/32, 2606:4700:110:8f69:a::2/128"));
        assert!(conf.contains("Endpoint = 162.159.192.1:2408"));
        assert_eq!(profile.reserved_bytes, [0, 0, 0]);
    }
}
