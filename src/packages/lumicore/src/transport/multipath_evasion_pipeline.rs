//! Second-Order Convergence: Multipath Evasion Pipeline
//!
//! Orchestrates multipath UDP bonded transport with NFQUEUE packet scrambling,
//! regional censorship evasion parameter synthesis, and zero-copy relay multiplexing.

use std::net::SocketAddr;
use std::time::Duration;
use crate::transport::multipath_udp_tunnel::{BondingMode, MultipathUdpTunnel, PathMetrics};
use crate::evasion::nfqueue_packet_scrambler::{NfqueuePacketScrambler, ScrambleAction};
use crate::evasion::censorship_profile_synthesizer::{CensorshipProfileSynthesizer, CensorshipRegion, RegionalEvasionProfile};

pub struct MultipathEvasionPipeline {
    pub tunnel: MultipathUdpTunnel,
    pub scrambler: NfqueuePacketScrambler,
    pub profile: RegionalEvasionProfile,
    total_processed_packets: u64,
}

impl MultipathEvasionPipeline {
    pub fn new(
        tunnel_id: impl Into<String>,
        mode: BondingMode,
        queue_num: u16,
        mark: u32,
        region: CensorshipRegion,
    ) -> Self {
        let synthesizer = CensorshipProfileSynthesizer::new();
        let profile = synthesizer.get_profile(region);
        let mut scrambler = NfqueuePacketScrambler::new(queue_num, mark);

        // Clamping TTL and MSS based on regional profile
        if profile.tcp_mss_clamp < 1200 {
            scrambler.set_ttl_hop_limit(48);
        } else {
            scrambler.set_ttl_hop_limit(64);
        }

        Self {
            tunnel: MultipathUdpTunnel::new(tunnel_id, mode),
            scrambler,
            profile,
            total_processed_packets: 0,
        }
    }

    pub fn register_path(&mut self, id: u32, local: SocketAddr, remote: SocketAddr, weight: u32) {
        self.tunnel.add_path(PathMetrics::new(id, local, remote, weight));
    }

    pub fn prepare_outbound_packet(&mut self, dest: SocketAddr, payload: &mut [u8]) -> Option<(u32, Vec<u8>)> {
        self.total_processed_packets += 1;

        // 1. Scramble/inspect packet
        let action = self.scrambler.process_ip_packet(dest, payload);
        match action {
            ScrambleAction::Drop => return None,
            _ => {}
        }

        // 2. Select path for egress
        let path_id = self.tunnel.select_path_for_egress()?;

        // 3. Encapsulate into multipath UDP frame
        let frame = self.tunnel.encapsulate_payload(path_id, payload)?;
        Some((path_id, frame))
    }

    pub fn total_packets(&self) -> u64 {
        self.total_processed_packets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multipath_evasion_pipeline() {
        let mut pipeline = MultipathEvasionPipeline::new(
            "pipeline-01",
            BondingMode::LowestLatency,
            2,
            0xCAFE,
            CensorshipRegion::Iran,
        );

        let local: SocketAddr = "127.0.0.1:8000".parse().unwrap();
        let remote: SocketAddr = "192.168.1.1:9000".parse().unwrap();
        pipeline.register_path(1, local, remote, 10);

        let mut dummy_packet = vec![0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06];
        dummy_packet.resize(40, 0);

        let dest: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let prepared = pipeline.prepare_outbound_packet(dest, &mut dummy_packet);
        assert!(prepared.is_some());

        let (path_id, frame) = prepared.unwrap();
        assert_eq!(path_id, 1);
        assert!(frame.len() > dummy_packet.len());
    }
}
