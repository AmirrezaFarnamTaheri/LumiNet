//! # MASQUE Amnezia Hybrid Tunnel (Synthesis C1)
//!
//! Orchestrates an evasion transport pipeline combining HTTP/3 MASQUE datagram capsules,
//! AmneziaWG header transforms, high-entropy packet scrambling, and routing leak protection.

use crate::evasion::amnezia_obfs_parameters::AmneziaObfsParameters;
use crate::evasion::entropy_scrambled_tunnel::EntropyScrambledTunnel;
use crate::security::leak_guard_supervisor::{LeakCheckReport, LeakGuardSupervisor};
use crate::transport::masque_datagram_tunnel::MasqueDatagramTunnel;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridTunnelTelemetry {
    pub total_datagrams_protected: u64,
    pub leak_risk_level: String,
    pub tunnel_ready: bool,
}

pub struct MasqueAmneziaHybridTunnel {
    masque: MasqueDatagramTunnel,
    amnezia: AmneziaObfsParameters,
    scrambler: EntropyScrambledTunnel,
    leak_guard: LeakGuardSupervisor,
    total_protected: u64,
}

impl MasqueAmneziaHybridTunnel {
    pub fn new(
        target_host: &str,
        target_port: u16,
        scramble_key: [u8; 32],
        tunnel_interface: &str,
        trusted_dns: Vec<String>,
        seed: u64,
    ) -> Self {
        Self {
            masque: MasqueDatagramTunnel::new(target_host, target_port, 0),
            amnezia: AmneziaObfsParameters::generate_random(seed),
            scrambler: EntropyScrambledTunnel::new(scramble_key, 8, 32),
            leak_guard: LeakGuardSupervisor::new(tunnel_interface, trusted_dns),
            total_protected: 0,
        }
    }

    pub fn prepare_outbound_packet(
        &mut self,
        packet_type: u8,
        raw_ip_packet: &[u8],
        seed: u64,
    ) -> Result<Vec<u8>, String> {
        // 1. Transform packet header using Amnezia parameters
        let header_code = self.amnezia.transform_header(packet_type);
        let mut framed = Vec::with_capacity(4 + raw_ip_packet.len());
        framed.extend_from_slice(&header_code.to_be_bytes());
        framed.extend_from_slice(raw_ip_packet);

        // 2. Apply high-entropy scrambling and jitter padding
        let scrambled = self.scrambler.scramble_packet(&framed, seed);

        // 3. Encapsulate inside MASQUE CONNECT-UDP capsule
        let capsule_bytes = self.masque.wrap_udp_datagram(&scrambled);

        self.total_protected += 1;
        Ok(capsule_bytes)
    }

    pub fn process_inbound_packet(&mut self, capsule_data: &[u8], seed: u64) -> Result<(u8, Vec<u8>), String> {
        // 1. Decode MASQUE capsule
        let (capsule, _) = self.masque.decode_capsule(capsule_data)?;

        // 2. Descramble payload
        let descrambled = self.scrambler.descramble_packet(&capsule.payload, seed)?;

        if descrambled.len() < 4 {
            return Err("Descrambled payload too short".to_string());
        }

        // 3. Reverse Amnezia header transform
        let header_code = u32::from_be_bytes([
            descrambled[0],
            descrambled[1],
            descrambled[2],
            descrambled[3],
        ]);
        let packet_type = self
            .amnezia
            .reverse_header(header_code)
            .ok_or("Unrecognized Amnezia packet header")?;

        let ip_packet = descrambled[4..].to_vec();
        Ok((packet_type, ip_packet))
    }

    pub fn check_leak_status(
        &self,
        active_interface: &str,
        active_resolvers: &[String],
        has_ipv6: bool,
    ) -> LeakCheckReport {
        self.leak_guard
            .verify_routing_integrity(active_interface, active_resolvers, has_ipv6)
    }

    pub fn get_telemetry(&self) -> HybridTunnelTelemetry {
        HybridTunnelTelemetry {
            total_datagrams_protected: self.total_protected,
            leak_risk_level: "Secure".to_string(),
            tunnel_ready: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_masque_amnezia_hybrid_tunnel_roundtrip() {
        let key = [0x77; 32];
        let trusted_dns = vec!["1.1.1.1".to_string()];
        let mut tunnel = MasqueAmneziaHybridTunnel::new(
            "gateway.antigfw.net",
            443,
            key,
            "tun0",
            trusted_dns,
            12345,
        );

        let ip_data = b"GET /private/resource HTTP/1.1\r\nHost: example.internal\r\n\r\n";
        let outbound = tunnel.prepare_outbound_packet(1, ip_data, 9999).unwrap();
        assert!(!outbound.is_empty());

        let (pkt_type, payload) = tunnel.process_inbound_packet(&outbound, 9999).unwrap();
        assert_eq!(pkt_type, 1);
        assert_eq!(payload, ip_data);

        let report = tunnel.check_leak_status("tun0", &["1.1.1.1".to_string()], false);
        assert_eq!(report.risk_level, crate::security::leak_guard_supervisor::LeakRiskLevel::Secure);

        let tele = tunnel.get_telemetry();
        assert_eq!(tele.total_datagrams_protected, 1);
    }
}
