//! Real-Time Network Flow Analyzer and DPI Engine
//!
//! Provides granular connection flow telemetry, layer 7 protocol identification,
//! packet/byte rate calculation, and network anomaly detection.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentifiedProtocol {
    Tls,
    Http,
    Dns,
    Ssh,
    Quic,
    WireGuard,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct FlowRecord {
    pub flow_id: u64,
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
    pub protocol: IdentifiedProtocol,
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub retransmissions: u64,
    pub start_time: Instant,
    pub last_seen: Instant,
}

impl FlowRecord {
    pub fn duration(&self) -> Duration {
        self.last_seen.duration_since(self.start_time)
    }

    pub fn retransmission_rate(&self) -> f64 {
        if self.packets_sent == 0 {
            0.0
        } else {
            (self.retransmissions as f64 / self.packets_sent as f64) * 100.0
        }
    }
}

pub struct FlowAnalyzerEngine {
    flows: HashMap<u64, FlowRecord>,
    next_flow_id: u64,
    total_analyzed_packets: u64,
}

impl FlowAnalyzerEngine {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
            next_flow_id: 1,
            total_analyzed_packets: 0,
        }
    }

    pub fn inspect_payload(payload: &[u8]) -> IdentifiedProtocol {
        if payload.is_empty() {
            return IdentifiedProtocol::Unknown;
        }

        // TLS ClientHello / Handshake (0x16 0x03 0x01/0x02/0x03)
        if payload.len() >= 3 && payload[0] == 0x16 && payload[1] == 0x03 {
            return IdentifiedProtocol::Tls;
        }

        // HTTP Methods
        if payload.starts_with(b"GET ")
            || payload.starts_with(b"POST ")
            || payload.starts_with(b"HTTP/1.")
            || payload.starts_with(b"HEAD ")
            || payload.starts_with(b"CONNECT ")
        {
            return IdentifiedProtocol::Http;
        }

        // SSH Identification Banner (e.g. "SSH-2.0-...")
        if payload.starts_with(b"SSH-") {
            return IdentifiedProtocol::Ssh;
        }

        // WireGuard handshake (Type 1: 0x01, Type 2: 0x02, followed by reserved 3 zero bytes)
        if payload.len() >= 4 && (payload[0] == 0x01 || payload[0] == 0x02) && payload[1..4] == [0, 0, 0] {
            return IdentifiedProtocol::WireGuard;
        }

        // QUIC Long Header (0x80 | ...) or Short Header
        if (payload[0] & 0x80) != 0 && payload.len() >= 5 {
            // Check for QUIC version field at offset 1..5
            let ver = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
            if ver == 0x00000001 || ver == 0xff00001d {
                return IdentifiedProtocol::Quic;
            }
        }

        IdentifiedProtocol::Unknown
    }

    pub fn register_flow(&mut self, src: SocketAddr, dst: SocketAddr, initial_payload: &[u8]) -> u64 {
        let fid = self.next_flow_id;
        self.next_flow_id += 1;

        let proto = Self::inspect_payload(initial_payload);
        let now = Instant::now();

        let rec = FlowRecord {
            flow_id: fid,
            src_addr: src,
            dst_addr: dst,
            protocol: proto,
            packets_sent: 1,
            packets_recv: 0,
            bytes_sent: initial_payload.len() as u64,
            bytes_recv: 0,
            retransmissions: 0,
            start_time: now,
            last_seen: now,
        };

        self.flows.insert(fid, rec);
        self.total_analyzed_packets += 1;
        fid
    }

    pub fn record_packet(
        &mut self,
        flow_id: u64,
        bytes: u64,
        is_egress: bool,
        is_retransmission: bool,
    ) -> bool {
        if let Some(flow) = self.flows.get_mut(&flow_id) {
            flow.last_seen = Instant::now();
            if is_egress {
                flow.packets_sent += 1;
                flow.bytes_sent += bytes;
                if is_retransmission {
                    flow.retransmissions += 1;
                }
            } else {
                flow.packets_recv += 1;
                flow.bytes_recv += bytes;
            }
            self.total_analyzed_packets += 1;
            true
        } else {
            false
        }
    }

    pub fn get_flow(&self, flow_id: u64) -> Option<&FlowRecord> {
        self.flows.get(&flow_id)
    }

    pub fn active_flow_count(&self) -> usize {
        self.flows.len()
    }

    pub fn detect_anomalies(&self, max_retransmission_rate: f64) -> Vec<u64> {
        self.flows
            .iter()
            .filter(|(_, f)| f.retransmission_rate() > max_retransmission_rate)
            .map(|(&id, _)| id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_analyzer_detection() {
        let mut analyzer = FlowAnalyzerEngine::new();
        let src: SocketAddr = "192.168.1.10:49152".parse().unwrap();
        let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();

        let tls_client_hello = [0x16, 0x03, 0x01, 0x00, 0x50];
        let fid = analyzer.register_flow(src, dst, &tls_client_hello);

        let flow = analyzer.get_flow(fid).expect("flow missing");
        assert_eq!(flow.protocol, IdentifiedProtocol::Tls);
        assert_eq!(flow.packets_sent, 1);
        assert_eq!(flow.bytes_sent, 5);

        // Record normal rx packet
        analyzer.record_packet(fid, 1024, false, false);
        // Record 3 retransmissions out of 4 egress
        analyzer.record_packet(fid, 500, true, true);
        analyzer.record_packet(fid, 500, true, true);
        analyzer.record_packet(fid, 500, true, true);

        let updated = analyzer.get_flow(fid).unwrap();
        assert_eq!(updated.packets_sent, 4);
        assert_eq!(updated.retransmissions, 3);
        assert!(updated.retransmission_rate() > 70.0);

        let anomalies = analyzer.detect_anomalies(50.0);
        assert_eq!(anomalies, vec![fid]);
    }
}
