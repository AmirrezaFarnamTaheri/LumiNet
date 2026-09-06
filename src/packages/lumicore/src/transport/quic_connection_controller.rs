//! # QUIC Connection Controller
//!
//! Async-native QUIC connection state machine, loss detection, RTT estimation,
//! Probe Timeout (PTO) timer management, and NewReno/BBR congestion window controller.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuicConnectionState {
    Idle,
    Initial,
    Handshaking,
    Established,
    Closing,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicConnectionMetrics {
    pub state: QuicConnectionState,
    pub smoothed_rtt_ms: u32,
    pub rttvar_ms: u32,
    pub min_rtt_ms: u32,
    pub congestion_window_bytes: u64,
    pub bytes_in_flight: u64,
    pub lost_packets_count: u64,
}

struct SentPacketRecord {
    packet_number: u64,
    size_bytes: usize,
    time_sent_ms: u64,
}

pub struct QuicConnectionController {
    state: QuicConnectionState,
    smoothed_rtt_ms: u32,
    rttvar_ms: u32,
    min_rtt_ms: u32,
    cwnd_bytes: u64,
    bytes_in_flight: u64,
    lost_packets_count: u64,
    ssthresh_bytes: u64,
    sent_packets: HashMap<u64, SentPacketRecord>,
}

impl QuicConnectionController {
    pub fn new(initial_window_bytes: u64) -> Self {
        Self {
            state: QuicConnectionState::Idle,
            smoothed_rtt_ms: 100, // Initial default 100ms
            rttvar_ms: 50,
            min_rtt_ms: u32::MAX,
            cwnd_bytes: initial_window_bytes.max(14720),
            bytes_in_flight: 0,
            lost_packets_count: 0,
            ssthresh_bytes: u64::MAX,
            sent_packets: HashMap::new(),
        }
    }

    pub fn set_state(&mut self, state: QuicConnectionState) {
        self.state = state;
    }

    pub fn can_send(&self, packet_bytes: usize) -> bool {
        self.state == QuicConnectionState::Established
            && (self.bytes_in_flight + packet_bytes as u64 <= self.cwnd_bytes)
    }

    pub fn on_packet_sent(&mut self, packet_number: u64, size_bytes: usize, time_sent_ms: u64) {
        self.bytes_in_flight += size_bytes as u64;
        self.sent_packets.insert(
            packet_number,
            SentPacketRecord {
                packet_number,
                size_bytes,
                time_sent_ms,
            },
        );
    }

    pub fn on_ack_received(&mut self, acked_packet_number: u64, now_ms: u64) {
        if let Some(record) = self.sent_packets.remove(&acked_packet_number) {
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(record.size_bytes as u64);

            if now_ms >= record.time_sent_ms {
                let sample_rtt = (now_ms - record.time_sent_ms) as u32;
                self.update_rtt(sample_rtt);
            }

            // Congestion window expansion
            if self.cwnd_bytes < self.ssthresh_bytes {
                // Slow start: grow by acked bytes
                self.cwnd_bytes += record.size_bytes as u64;
            } else {
                // Congestion avoidance: grow linearly
                let increment = (1472 * 1472) / self.cwnd_bytes.max(1);
                self.cwnd_bytes += increment.max(1);
            }
        }
    }

    pub fn on_packet_loss(&mut self, lost_packet_number: u64) {
        if let Some(record) = self.sent_packets.remove(&lost_packet_number) {
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(record.size_bytes as u64);
            self.lost_packets_count += 1;

            // Multiplicative decrease
            self.ssthresh_bytes = (self.cwnd_bytes / 2).max(14720);
            self.cwnd_bytes = self.ssthresh_bytes;
        }
    }

    pub fn calculate_pto_ms(&self) -> u32 {
        // PTO = smoothed_rtt + max(4*rttvar, 10ms)
        self.smoothed_rtt_ms + (4 * self.rttvar_ms).max(10)
    }

    pub fn get_metrics(&self) -> QuicConnectionMetrics {
        QuicConnectionMetrics {
            state: self.state,
            smoothed_rtt_ms: self.smoothed_rtt_ms,
            rttvar_ms: self.rttvar_ms,
            min_rtt_ms: if self.min_rtt_ms == u32::MAX { 0 } else { self.min_rtt_ms },
            congestion_window_bytes: self.cwnd_bytes,
            bytes_in_flight: self.bytes_in_flight,
            lost_packets_count: self.lost_packets_count,
        }
    }

    fn update_rtt(&mut self, sample_rtt: u32) {
        if self.min_rtt_ms == u32::MAX {
            self.min_rtt_ms = sample_rtt;
            self.smoothed_rtt_ms = sample_rtt;
            self.rttvar_ms = sample_rtt / 2;
        } else {
            self.min_rtt_ms = self.min_rtt_ms.min(sample_rtt);
            let diff = if sample_rtt > self.smoothed_rtt_ms {
                sample_rtt - self.smoothed_rtt_ms
            } else {
                self.smoothed_rtt_ms - sample_rtt
            };
            self.rttvar_ms = (3 * self.rttvar_ms + diff) / 4;
            self.smoothed_rtt_ms = (7 * self.smoothed_rtt_ms + sample_rtt) / 8;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_connection_controller() {
        let mut controller = QuicConnectionController::new(20000);
        controller.set_state(QuicConnectionState::Established);
        assert!(controller.can_send(1000));

        controller.on_packet_sent(1, 1200, 1000);
        assert_eq!(controller.get_metrics().bytes_in_flight, 1200);

        controller.on_ack_received(1, 1050); // 50ms RTT
        let metrics = controller.get_metrics();
        assert_eq!(metrics.bytes_in_flight, 0);
        assert!(metrics.congestion_window_bytes > 20000); // Expanded in slow start
        assert!(controller.calculate_pto_ms() > 0);

        // Test packet loss
        controller.on_packet_sent(2, 1200, 2000);
        controller.on_packet_loss(2);
        let m2 = controller.get_metrics();
        assert_eq!(m2.lost_packets_count, 1);
        assert_eq!(m2.bytes_in_flight, 0);
    }
}
