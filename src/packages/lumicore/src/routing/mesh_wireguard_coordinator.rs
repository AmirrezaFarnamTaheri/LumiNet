// Pure Rust implementation: WireGuard Mesh Coordinator

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerConnectionMode {
    Direct(SocketAddr),
    DerpRelay(u16), // DERP region ID
}

#[derive(Debug, Clone)]
pub struct MeshPeer {
    pub peer_id: String,
    pub public_key: [u8; 32],
    pub virtual_ip: Ipv4Addr,
    pub allowed_ips: Vec<String>,
    pub endpoints: Vec<SocketAddr>,
    pub derp_region_id: u16,
    pub last_handshake_ms: u64,
    pub is_exit_node: bool,
}

pub struct MeshWireguardCoordinator {
    pub local_peer_id: String,
    pub local_virtual_ip: Ipv4Addr,
    pub peers: HashMap<String, MeshPeer>,
    pub derp_relays: HashMap<u16, String>,
}

impl MeshWireguardCoordinator {
    pub fn new(local_peer_id: impl Into<String>, local_virtual_ip: Ipv4Addr) -> Self {
        Self {
            local_peer_id: local_peer_id.into(),
            local_virtual_ip,
            peers: HashMap::new(),
            derp_relays: HashMap::new(),
        }
    }

    pub fn register_derp_relay(&mut self, region_id: u16, hostname: impl Into<String>) {
        self.derp_relays.insert(region_id, hostname.into());
    }

    pub fn register_peer(&mut self, peer: MeshPeer) {
        self.peers.insert(peer.peer_id.clone(), peer);
    }

    pub fn update_peer_endpoint(&mut self, peer_id: &str, endpoint: SocketAddr) -> bool {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            if !peer.endpoints.contains(&endpoint) {
                peer.endpoints.insert(0, endpoint);
            }
            true
        } else {
            false
        }
    }

    pub fn select_best_endpoint(&self, peer_id: &str, now_ms: u64) -> Option<PeerConnectionMode> {
        let peer = self.peers.get(peer_id)?;
        
        // If handshake is recent (< 180 seconds) and we have an endpoint, use direct UDP
        let is_recent = now_ms.saturating_sub(peer.last_handshake_ms) < 180_000;
        if is_recent && !peer.endpoints.is_empty() {
            Some(PeerConnectionMode::Direct(peer.endpoints[0]))
        } else if self.derp_relays.contains_key(&peer.derp_region_id) {
            Some(PeerConnectionMode::DerpRelay(peer.derp_region_id))
        } else if !peer.endpoints.is_empty() {
            Some(PeerConnectionMode::Direct(peer.endpoints[0]))
        } else {
            None
        }
    }

    pub fn lookup_route(&self, destination: Ipv4Addr) -> Option<String> {
        // Exact match on virtual IP first
        for (peer_id, peer) in &self.peers {
            if peer.virtual_ip == destination {
                return Some(peer_id.clone());
            }
        }

        // Subnet matching across allowed_ips
        for (peer_id, peer) in &self.peers {
            for cidr in &peer.allowed_ips {
                if is_ip_in_cidr(destination, cidr) {
                    return Some(peer_id.clone());
                }
            }
        }

        None
    }

    pub fn elect_exit_node(&self) -> Option<String> {
        self.peers
            .iter()
            .filter(|(_, p)| p.is_exit_node)
            .min_by_key(|(_, p)| p.last_handshake_ms)
            .map(|(id, _)| id.clone())
    }

    pub fn generate_wireguard_peer_config(&self, peer_id: &str) -> Result<String, String> {
        let peer = self.peers.get(peer_id).ok_or_else(|| "Peer not found".to_string())?;
        
        let pub_key_hex = hex_encode(&peer.public_key);
        let allowed_str = if peer.allowed_ips.is_empty() {
            format!("{}/32", peer.virtual_ip)
        } else {
            peer.allowed_ips.join(", ")
        };

        let mut conf = String::new();
        conf.push_str("[Peer]\n");
        conf.push_str(&format!("PublicKey = {}\n", pub_key_hex));
        conf.push_str(&format!("AllowedIPs = {}\n", allowed_str));
        if let Some(ep) = peer.endpoints.first() {
            conf.push_str(&format!("Endpoint = {}\n", ep));
            conf.push_str("PersistentKeepalive = 25\n");
        }

        Ok(conf)
    }
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn is_ip_in_cidr(ip: Ipv4Addr, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    let network = match parts[0].parse::<Ipv4Addr>() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    let prefix = match parts[1].parse::<u8>() {
        Ok(p) if p <= 32 => p,
        Err(_) | Ok(_) => return false,
    };

    let ip_u32 = u32::from(ip);
    let net_u32 = u32::from(network);
    let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };

    (ip_u32 & mask) == (net_u32 & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mesh_peer_registration_and_route() {
        let mut coord = MeshWireguardCoordinator::new("node-local", Ipv4Addr::new(100, 64, 0, 1));
        coord.register_derp_relay(1, "derp-nyc.luminet.net");

        let peer = MeshPeer {
            peer_id: "peer-remote".to_string(),
            public_key: [7u8; 32],
            virtual_ip: Ipv4Addr::new(100, 64, 0, 2),
            allowed_ips: vec!["10.50.0.0/16".to_string()],
            endpoints: vec!["198.51.100.10:51820".parse().unwrap()],
            derp_region_id: 1,
            last_handshake_ms: 100_000,
            is_exit_node: true,
        };

        coord.register_peer(peer);

        // Lookup exact virtual IP
        assert_eq!(coord.lookup_route(Ipv4Addr::new(100, 64, 0, 2)), Some("peer-remote".to_string()));
        // Lookup subnet
        assert_eq!(coord.lookup_route(Ipv4Addr::new(10, 50, 4, 99)), Some("peer-remote".to_string()));
        // Lookup unknown
        assert_eq!(coord.lookup_route(Ipv4Addr::new(8, 8, 8, 8)), None);
    }

    #[test]
    fn test_endpoint_selection_and_config() {
        let mut coord = MeshWireguardCoordinator::new("node-local", Ipv4Addr::new(100, 64, 0, 1));
        coord.register_derp_relay(1, "derp-nyc.luminet.net");

        let peer = MeshPeer {
            peer_id: "peer-1".to_string(),
            public_key: [0x42; 32],
            virtual_ip: Ipv4Addr::new(100, 64, 0, 10),
            allowed_ips: vec![],
            endpoints: vec!["203.0.113.5:51820".parse().unwrap()],
            derp_region_id: 1,
            last_handshake_ms: 1000,
            is_exit_node: false,
        };
        coord.register_peer(peer);

        // With fresh handshake -> Direct mode
        let mode = coord.select_best_endpoint("peer-1", 5000).unwrap();
        assert_eq!(mode, PeerConnectionMode::Direct("203.0.113.5:51820".parse().unwrap()));

        // Old handshake (> 180s) -> DERP relay fallback
        let fallback = coord.select_best_endpoint("peer-1", 300_000).unwrap();
        assert_eq!(fallback, PeerConnectionMode::DerpRelay(1));

        // Generate WG peer config
        let cfg = coord.generate_wireguard_peer_config("peer-1").unwrap();
        assert!(cfg.contains("[Peer]"));
        assert!(cfg.contains("PersistentKeepalive = 25"));
    }
}
