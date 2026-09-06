// Pure Rust implementation: NAT Traversal Tunnel & Hole Punching

use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    OpenInternet,
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    SymmetricNat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchState {
    Initial,
    Probing,
    Established,
    FailedRelayFallback,
}

#[derive(Debug, Clone)]
pub struct PeerCandidate {
    pub peer_id: String,
    pub local_endpoint: SocketAddr,
    pub reflexive_endpoint: SocketAddr,
    pub nat_type: NatType,
}

pub struct NatTraversalTunnel {
    pub local_peer_id: String,
    pub local_nat_type: NatType,
    pub peers: HashMap<String, PunchState>,
    pub punch_magic: u32,
}

impl NatTraversalTunnel {
    pub const DEFAULT_MAGIC: u32 = 0x564E5431; // "VNT1"

    pub fn new(local_peer_id: impl Into<String>, local_nat_type: NatType) -> Self {
        Self {
            local_peer_id: local_peer_id.into(),
            local_nat_type,
            peers: HashMap::new(),
            punch_magic: Self::DEFAULT_MAGIC,
        }
    }

    pub fn can_direct_hole_punch(nat_a: NatType, nat_b: NatType) -> bool {
        match (nat_a, nat_b) {
            // Symmetric to Symmetric cannot hole punch with standard UDP hole punching
            (NatType::SymmetricNat, NatType::SymmetricNat) => false,
            // Port Restricted to Symmetric typically fails
            (NatType::PortRestrictedCone, NatType::SymmetricNat)
            | (NatType::SymmetricNat, NatType::PortRestrictedCone) => false,
            // All other combinations are punchable
            _ => true,
        }
    }

    pub fn craft_punch_packet(&self, sequence: u32) -> Vec<u8> {
        let mut packet = Vec::with_capacity(16 + self.local_peer_id.len());
        packet.extend_from_slice(&self.punch_magic.to_be_bytes());
        packet.extend_from_slice(&sequence.to_be_bytes());
        let id_bytes = self.local_peer_id.as_bytes();
        packet.extend_from_slice(&(id_bytes.len() as u16).to_be_bytes());
        packet.extend_from_slice(id_bytes);
        packet
    }

    pub fn parse_punch_packet(&self, buffer: &[u8]) -> Option<(u32, String)> {
        if buffer.len() < 10 {
            return None;
        }
        let magic = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
        if magic != self.punch_magic {
            return None;
        }
        let seq = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
        let id_len = u16::from_be_bytes([buffer[8], buffer[9]]) as usize;
        if buffer.len() < 10 + id_len {
            return None;
        }
        let peer_id = std::str::from_utf8(&buffer[10..10 + id_len]).ok()?.to_string();
        Some((seq, peer_id))
    }

    pub fn initiate_peer_punch(&mut self, candidate: &PeerCandidate) -> PunchState {
        if Self::can_direct_hole_punch(self.local_nat_type, candidate.nat_type) {
            self.peers.insert(candidate.peer_id.clone(), PunchState::Probing);
            PunchState::Probing
        } else {
            self.peers.insert(candidate.peer_id.clone(), PunchState::FailedRelayFallback);
            PunchState::FailedRelayFallback
        }
    }

    pub fn mark_established(&mut self, peer_id: &str) -> bool {
        if let Some(state) = self.peers.get_mut(peer_id) {
            *state = PunchState::Established;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_punchability_matrix() {
        assert!(NatTraversalTunnel::can_direct_hole_punch(NatType::FullCone, NatType::SymmetricNat));
        assert!(NatTraversalTunnel::can_direct_hole_punch(NatType::RestrictedCone, NatType::PortRestrictedCone));
        assert!(!NatTraversalTunnel::can_direct_hole_punch(NatType::SymmetricNat, NatType::SymmetricNat));
        assert!(!NatTraversalTunnel::can_direct_hole_punch(NatType::PortRestrictedCone, NatType::SymmetricNat));
    }

    #[test]
    fn test_punch_packet_roundtrip() {
        let tunnel = NatTraversalTunnel::new("peer-node-a", NatType::RestrictedCone);
        let packet = tunnel.craft_punch_packet(1042);
        
        let parsed = tunnel.parse_punch_packet(&packet);
        assert_eq!(parsed, Some((1042, "peer-node-a".to_string())));
    }

    #[test]
    fn test_initiate_punch_state() {
        let mut tunnel = NatTraversalTunnel::new("local-1", NatType::PortRestrictedCone);
        
        let candidate_cone = PeerCandidate {
            peer_id: "remote-cone".to_string(),
            local_endpoint: "192.168.1.10:5000".parse().unwrap(),
            reflexive_endpoint: "203.0.113.10:5000".parse().unwrap(),
            nat_type: NatType::FullCone,
        };
        assert_eq!(tunnel.initiate_peer_punch(&candidate_cone), PunchState::Probing);

        let candidate_sym = PeerCandidate {
            peer_id: "remote-sym".to_string(),
            local_endpoint: "192.168.1.20:5000".parse().unwrap(),
            reflexive_endpoint: "203.0.113.20:5000".parse().unwrap(),
            nat_type: NatType::SymmetricNat,
        };
        assert_eq!(tunnel.initiate_peer_punch(&candidate_sym), PunchState::FailedRelayFallback);
    }
}
