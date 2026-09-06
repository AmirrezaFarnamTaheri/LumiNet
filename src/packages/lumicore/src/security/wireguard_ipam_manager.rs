//! # WireGuard IPAM Manager
//!
//! WireGuard IP address management (IPAM), peer key registry, dynamic subnet allocator,
//! and server/client interface configuration synthesizer.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireguardPeer {
    pub public_key: String,
    pub assigned_ip: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub enabled: bool,
}

pub struct WireguardIpamManager {
    subnet_prefix: String,
    next_ip_suffix: u8,
    server_ip: String,
    listen_port: u16,
    peers: HashMap<String, WireguardPeer>, // public_key -> peer
    ip_to_key: HashMap<String, String>,
}

impl WireguardIpamManager {
    pub fn new(subnet_prefix: &str, listen_port: u16) -> Result<Self, String> {
        let parts: Vec<&str> = subnet_prefix.split('.').collect();
        if parts.len() != 3 {
            return Err("Subnet prefix must have 3 octets, e.g. 10.14.0".to_string());
        }

        let server_ip = format!("{}.1", subnet_prefix);
        Ok(Self {
            subnet_prefix: subnet_prefix.to_string(),
            next_ip_suffix: 2,
            server_ip,
            listen_port,
            peers: HashMap::new(),
            ip_to_key: HashMap::new(),
        })
    }

    pub fn allocate_peer(&mut self, public_key: &str) -> Result<WireguardPeer, String> {
        if let Some(existing) = self.peers.get(public_key) {
            return Ok(existing.clone());
        }

        if self.next_ip_suffix >= 254 {
            return Err("Subnet exhausted".to_string());
        }

        let assigned_ip = format!("{}.{}", self.subnet_prefix, self.next_ip_suffix);
        self.next_ip_suffix += 1;

        let peer = WireguardPeer {
            public_key: public_key.to_string(),
            assigned_ip: assigned_ip.clone(),
            allowed_ips: vec![format!("{}/32", assigned_ip)],
            endpoint: None,
            enabled: true,
        };

        self.ip_to_key.insert(assigned_ip, public_key.to_string());
        self.peers.insert(public_key.to_string(), peer.clone());
        Ok(peer)
    }

    pub fn release_peer(&mut self, public_key: &str) -> Result<(), String> {
        if let Some(peer) = self.peers.remove(public_key) {
            self.ip_to_key.remove(&peer.assigned_ip);
            Ok(())
        } else {
            Err("Peer not found".to_string())
        }
    }

    pub fn generate_server_config(&self, server_private_key: &str) -> String {
        let mut out = Vec::new();
        out.push("[Interface]".to_string());
        out.push(format!("Address = {}/24", self.server_ip));
        out.push(format!("ListenPort = {}", self.listen_port));
        out.push(format!("PrivateKey = {}", server_private_key));
        out.push("".to_string());

        for peer in self.peers.values() {
            if peer.enabled {
                out.push("[Peer]".to_string());
                out.push(format!("PublicKey = {}", peer.public_key));
                out.push(format!("AllowedIPs = {}", peer.allowed_ips.join(", ")));
                if let Some(ref ep) = peer.endpoint {
                    out.push(format!("Endpoint = {}", ep));
                }
                out.push("".to_string());
            }
        }

        out.join("\n")
    }

    pub fn generate_client_config(
        &self,
        peer_public_key: &str,
        peer_private_key: &str,
        server_public_key: &str,
        server_endpoint: &str,
    ) -> Result<String, String> {
        let peer = self.peers.get(peer_public_key).ok_or("Peer not registered")?;

        let mut out = Vec::new();
        out.push("[Interface]".to_string());
        out.push(format!("Address = {}/32", peer.assigned_ip));
        out.push(format!("PrivateKey = {}", peer_private_key));
        out.push("DNS = 1.1.1.1".to_string());
        out.push("".to_string());

        out.push("[Peer]".to_string());
        out.push(format!("PublicKey = {}", server_public_key));
        out.push(format!("Endpoint = {}", server_endpoint));
        out.push("AllowedIPs = 0.0.0.0/0, ::/0".to_string());
        out.push("PersistentKeepalive = 25".to_string());

        Ok(out.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipam_allocation_and_config() {
        let mut ipam = WireguardIpamManager::new("10.88.0", 51820).unwrap();
        let peer1 = ipam.allocate_peer("client_pubkey_11111111111111111111111111=").unwrap();
        assert_eq!(peer1.assigned_ip, "10.88.0.2");

        let peer2 = ipam.allocate_peer("client_pubkey_22222222222222222222222222=").unwrap();
        assert_eq!(peer2.assigned_ip, "10.88.0.3");

        let srv_cfg = ipam.generate_server_config("server_private_key_xyz=");
        assert!(srv_cfg.contains("Address = 10.88.0.1/24"));
        assert!(srv_cfg.contains("client_pubkey_11111111111111111111111111="));

        let client_cfg = ipam.generate_client_config(
            "client_pubkey_11111111111111111111111111=",
            "client_privkey_11111111111111111111111111=",
            "server_pubkey_abc=",
            "203.0.113.10:51820",
        ).unwrap();
        assert!(client_cfg.contains("Address = 10.88.0.2/32"));
        assert!(client_cfg.contains("server_pubkey_abc="));

        ipam.release_peer("client_pubkey_11111111111111111111111111=").unwrap();
        assert!(ipam.peers.get("client_pubkey_11111111111111111111111111=").is_none());
    }
}
