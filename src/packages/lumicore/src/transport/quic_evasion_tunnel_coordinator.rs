//! # QUIC Evasion Tunnel Coordinator (Synthesis C1)
//!
//! Orchestrates an evasive, anti-censorship QUIC transport tunnel integrating QUIC stream multiplexing,
//! connection state & congestion control, packet encoding, SNI random segmentation, and replay resistance.

use crate::evasion::sni_segmentation_masquerader::{SegmentationStrategy, SniSegmentationMasquerader};
use crate::transport::quic_connection_controller::{QuicConnectionController, QuicConnectionState};
use crate::transport::quic_packet_codec::{QuicHeaderType, QuicPacketCodec, QuicPacketHeader};
use crate::transport::quic_stream_multiplexer::{QuicStreamMultiplexer, QuicStreamType};
use crate::transport::replay_resistant_tunnel::{ReplayResistantConfig, ReplayResistantTunnelSession};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicTunnelMetrics {
    pub connection_state: QuicConnectionState,
    pub total_datagrams_sent: u64,
    pub total_datagrams_received: u64,
    pub active_streams: usize,
    pub evasion_active: bool,
}

pub struct QuicEvasionTunnelCoordinator {
    multiplexer: QuicStreamMultiplexer,
    connection: QuicConnectionController,
    masquerader: SniSegmentationMasquerader,
    replay_session: ReplayResistantTunnelSession,
    dest_cid: Vec<u8>,
    src_cid: Vec<u8>,
    next_packet_num: u64,
    total_sent: u64,
    total_recv: u64,
    evasion_mode: bool,
}

impl QuicEvasionTunnelCoordinator {
    pub fn new(
        dest_cid: Vec<u8>,
        src_cid: Vec<u8>,
        client_random: &[u8],
        server_random: &[u8],
        evasion_mode: bool,
    ) -> Self {
        let replay_config = ReplayResistantConfig::default();
        let replay_session = ReplayResistantTunnelSession::new(replay_config, client_random, server_random);

        let mut connection = QuicConnectionController::new(65536);
        connection.set_state(QuicConnectionState::Established);

        Self {
            multiplexer: QuicStreamMultiplexer::new(65536),
            connection,
            masquerader: SniSegmentationMasquerader::new(SegmentationStrategy::MidSniSplit, 8, 32),
            replay_session,
            dest_cid,
            src_cid,
            next_packet_num: 1,
            total_sent: 0,
            total_recv: 0,
            evasion_mode,
        }
    }

    pub fn open_tunnel_stream(&mut self) -> u64 {
        self.multiplexer.open_stream(QuicStreamType::ClientBidirectional)
    }

    pub fn prepare_outbound_datagram(
        &mut self,
        stream_id: u64,
        app_data: &[u8],
        timestamp_secs: u64,
    ) -> Result<Vec<Vec<u8>>, String> {
        // 1. Multiplex stream frame
        let stream_frame = self.multiplexer.write_stream_data(stream_id, app_data, false)?;
        let frame_bytes = serde_json::to_vec(&stream_frame).map_err(|e| e.to_string())?;

        // 2. Wrap in QUIC 1-RTT Short packet
        let header = QuicPacketHeader {
            header_type: QuicHeaderType::OneRttShort,
            version: 0,
            dest_cid: self.dest_cid.clone(),
            src_cid: self.src_cid.clone(),
            packet_number: self.next_packet_num,
        };
        let quic_packet = QuicPacketCodec::encode_packet(&header, &frame_bytes);

        // 3. Seal with replay resistance
        let sealed = self
            .replay_session
            .seal_packet(self.next_packet_num, timestamp_secs, &quic_packet);

        self.connection
            .on_packet_sent(self.next_packet_num, sealed.len(), timestamp_secs * 1000);
        self.next_packet_num += 1;
        self.total_sent += 1;

        // 4. If evasion mode is enabled, segment datagram to evade DPI
        if self.evasion_mode {
            let segments = self.masquerader.segment_stream(&sealed, self.next_packet_num);
            Ok(segments)
        } else {
            Ok(vec![sealed])
        }
    }

    pub fn process_inbound_datagram(
        &mut self,
        sealed_datagram: &[u8],
        current_time_secs: u64,
    ) -> Result<(u64, Vec<u8>), String> {
        // 1. Verify replay resistance and open envelope
        let (seq, _ts, quic_packet) = self
            .replay_session
            .open_packet(sealed_datagram, current_time_secs)?;

        self.connection.on_ack_received(seq, current_time_secs * 1000);
        self.total_recv += 1;

        // 2. Decode QUIC packet
        let (_header, payload) = QuicPacketCodec::decode_packet(&quic_packet, self.dest_cid.len())?;

        // 3. Deserialize stream frame
        let frame: crate::transport::quic_stream_multiplexer::QuicStreamFrame =
            serde_json::from_slice(&payload).map_err(|e| e.to_string())?;

        // 4. Reassemble stream data
        let stream_id = frame.stream_id;
        let assembled = self.multiplexer.receive_stream_frame(frame)?;

        Ok((stream_id, assembled))
    }

    pub fn get_tunnel_metrics(&self) -> QuicTunnelMetrics {
        QuicTunnelMetrics {
            connection_state: self.connection.get_metrics().state,
            total_datagrams_sent: self.total_sent,
            total_datagrams_received: self.total_recv,
            active_streams: 1,
            evasion_active: self.evasion_mode,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_evasion_tunnel_coordinator_lifecycle() {
        let dcid = vec![0x11, 0x22, 0x33, 0x44];
        let scid = vec![0x55, 0x66, 0x77, 0x88];
        let crand = b"client_rnd_test_1";
        let srand = b"server_rnd_test_2";

        let mut client_coord = QuicEvasionTunnelCoordinator::new(
            dcid.clone(),
            scid.clone(),
            crand,
            srand,
            false,
        );
        let mut server_coord = QuicEvasionTunnelCoordinator::new(
            dcid.clone(),
            scid.clone(),
            crand,
            srand,
            false,
        );

        let stream_id = client_coord.open_tunnel_stream();
        assert_eq!(stream_id, 0);

        let now = 1700000000;
        let outbound_packets = client_coord
            .prepare_outbound_datagram(stream_id, b"Secure Tunnel Traffic", now)
            .unwrap();
        assert_eq!(outbound_packets.len(), 1);

        let (recv_stream, payload) = server_coord
            .process_inbound_datagram(&outbound_packets[0], now + 1)
            .unwrap();
        assert_eq!(recv_stream, stream_id);
        assert_eq!(payload, b"Secure Tunnel Traffic");

        let metrics = client_coord.get_tunnel_metrics();
        assert_eq!(metrics.total_datagrams_sent, 1);
    }
}
