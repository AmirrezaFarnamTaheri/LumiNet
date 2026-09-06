//! # TUN VPN Manager
//!
//! TUN-based VPN with virtual IP assignment and packet routing.
//!
//! Creates a TUN interface, assigns virtual IPs from a pool,
//! and routes packets between peers through encrypted tunnels.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::RwLock;

/// VPN packet signature constants.
/// Used to identify packet types in the tunnel protocol.
pub const SIG_DHCP_REQ: [u8; 4] = [0x56, 0x50, 0x4E, 0x01]; // "VPN\x01"
pub const SIG_DHCP_RES: [u8; 4] = [0x56, 0x50, 0x4E, 0x02]; // "VPN\x02"
pub const SIG_TUNNEL: [u8; 4] = [0x56, 0x50, 0x4E, 0x03]; // "VPN\x03"
pub const SIG_BYE: [u8; 4] = [0x56, 0x50, 0x4E, 0x04]; // "VPN\x04"

/// Virtual IP address pool.
#[derive(Debug, Clone)]
pub struct IPPool {
    /// Network address (e.g., 10.0.0.0).
    network: Ipv4Addr,
    /// Subnet mask (e.g., 255.255.255.0).
    mask: Ipv4Addr,
    /// Gateway IP (first usable).
    gateway: Ipv4Addr,
    /// Next IP to assign.
    next_ip: u32,
    /// Allocated IPs.
    allocated: HashMap<String, Ipv4Addr>,
}

impl IPPool {
    /// Creates a new IP pool.
    pub fn new(network: Ipv4Addr, mask: Ipv4Addr) -> Self {
        let network_u32 = ip_to_u32(&network);
        let gateway = u32_to_ip(network_u32 + 1);
        Self {
            network,
            mask,
            gateway,
            next_ip: 2, // Start from network + 2
            allocated: HashMap::new(),
        }
    }

    /// Allocates an IP for a peer.
    pub fn allocate(&mut self, peer_id: &str) -> Option<Ipv4Addr> {
        if let Some(ip) = self.allocated.get(peer_id) {
            return Some(*ip);
        }

        let network_u32 = ip_to_u32(&self.network);
        let mask_u32 = ip_to_u32(&self.mask);
        let max_hosts = !mask_u32;

        if self.next_ip >= max_hosts - 1 {
            return None; // Pool exhausted
        }

        let ip = u32_to_ip(network_u32 + self.next_ip);
        self.next_ip += 1;
        self.allocated.insert(peer_id.to_string(), ip);
        Some(ip)
    }

    /// Releases an IP allocation.
    pub fn release(&mut self, peer_id: &str) {
        self.allocated.remove(peer_id);
    }

    /// Returns the gateway IP.
    pub fn gateway(&self) -> Ipv4Addr {
        self.gateway
    }

    /// Returns allocated count.
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }
}

/// Peer information.
#[derive(Debug, Clone)]
pub struct Peer {
    pub id: String,
    pub virtual_ip: Ipv4Addr,
    pub endpoint: SocketAddr,
    pub public_key: Vec<u8>,
    pub last_seen: std::time::Instant,
}

/// VPN session manager.
pub struct VpnSessionManager {
    peers: Arc<RwLock<HashMap<String, Peer>>>,
    ip_pool: Arc<RwLock<IPPool>>,
}

impl VpnSessionManager {
    pub fn new(network: Ipv4Addr, mask: Ipv4Addr) -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            ip_pool: Arc::new(RwLock::new(IPPool::new(network, mask))),
        }
    }

    /// Registers a new peer and assigns a virtual IP.
    pub async fn register_peer(
        &self,
        peer_id: String,
        endpoint: SocketAddr,
        public_key: Vec<u8>,
    ) -> Option<Ipv4Addr> {
        let mut pool = self.ip_pool.write().await;
        let ip = pool.allocate(&peer_id)?;

        let peer = Peer {
            id: peer_id.clone(),
            virtual_ip: ip,
            endpoint,
            public_key,
            last_seen: std::time::Instant::now(),
        };

        let mut peers = self.peers.write().await;
        peers.insert(peer_id, peer);
        Some(ip)
    }

    /// Removes a peer.
    pub async fn remove_peer(&self, peer_id: &str) {
        let mut peers = self.peers.write().await;
        peers.remove(peer_id);
        let mut pool = self.ip_pool.write().await;
        pool.release(peer_id);
    }

    /// Looks up a peer by virtual IP.
    pub async fn lookup_by_ip(&self, ip: &Ipv4Addr) -> Option<Peer> {
        let peers = self.peers.read().await;
        peers.values().find(|p| p.virtual_ip == *ip).cloned()
    }

    /// Returns the number of active peers.
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }
}

fn ip_to_u32(ip: &Ipv4Addr) -> u32 {
    let o = ip.octets();
    u32::from_be_bytes(o)
}

fn u32_to_ip(n: u32) -> Ipv4Addr {
    Ipv4Addr::from(n.to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_pool() {
        let mut pool = IPPool::new(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(pool.gateway(), Ipv4Addr::new(10, 0, 0, 1));

        let ip1 = pool.allocate("peer1").unwrap();
        assert_eq!(ip1, Ipv4Addr::new(10, 0, 0, 2));

        let ip2 = pool.allocate("peer2").unwrap();
        assert_eq!(ip2, Ipv4Addr::new(10, 0, 0, 3));

        // Same peer gets same IP
        let ip1_again = pool.allocate("peer1").unwrap();
        assert_eq!(ip1_again, ip1);

        assert_eq!(pool.allocated_count(), 2);
    }

    #[test]
    fn test_packet_signatures() {
        assert_ne!(SIG_DHCP_REQ, SIG_DHCP_RES);
        assert_ne!(SIG_TUNNEL, SIG_BYE);
        assert_eq!(SIG_DHCP_REQ[0], b'V'); // "VPN"
    }
}
