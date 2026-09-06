//! Multipath UDP Tunnel Engine
//!
//! Provides aggregated and bonded multipath tunneling over UDP with
//! dynamic RTT probing, packet loss tracking, and latency-optimized path switching.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    Active,
    Standby,
    Degraded,
    Down,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondingMode {
    RoundRobin,
    LowestLatency,
    RedundantDuplicate,
    WeightedLossRatio,
}

#[derive(Debug, Clone)]
pub struct PathMetrics {
    pub path_id: u32,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub rtt_ms: f64,
    pub loss_percentage: f64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub state: PathState,
    pub weight: u32,
    pub last_heartbeat: Instant,
}

impl PathMetrics {
    pub fn new(path_id: u32, local: SocketAddr, remote: SocketAddr, weight: u32) -> Self {
        Self {
            path_id,
            local_addr: local,
            remote_addr: remote,
            rtt_ms: 0.0,
            loss_percentage: 0.0,
            tx_bytes: 0,
            rx_bytes: 0,
            state: PathState::Active,
            weight: weight.max(1),
            last_heartbeat: Instant::now(),
        }
    }

    pub fn record_heartbeat_reply(&mut self, latency_ms: f64, packet_lost: bool) {
        if self.rtt_ms <= 0.0 {
            self.rtt_ms = latency_ms;
        } else {
            // Exponential moving average (alpha = 0.2)
            self.rtt_ms = self.rtt_ms * 0.8 + latency_ms * 0.2;
        }

        let loss_sample = if packet_lost { 100.0 } else { 0.0 };
        self.loss_percentage = self.loss_percentage * 0.9 + loss_sample * 0.1;
        self.last_heartbeat = Instant::now();

        if self.loss_percentage > 50.0 {
            self.state = PathState::Degraded;
        } else if self.loss_percentage > 90.0 {
            self.state = PathState::Down;
        } else {
            self.state = PathState::Active;
        }
    }
}

pub struct MultipathUdpTunnel {
    pub tunnel_id: String,
    pub mode: BondingMode,
    paths: HashMap<u32, PathMetrics>,
    round_robin_counter: usize,
    heartbeat_interval: Duration,
    loss_threshold: f64,
}

impl MultipathUdpTunnel {
    pub fn new(tunnel_id: impl Into<String>, mode: BondingMode) -> Self {
        Self {
            tunnel_id: tunnel_id.into(),
            mode,
            paths: HashMap::new(),
            round_robin_counter: 0,
            heartbeat_interval: Duration::from_millis(500),
            loss_threshold: 40.0,
        }
    }

    pub fn add_path(&mut self, path: PathMetrics) {
        self.paths.insert(path.path_id, path);
    }

    pub fn remove_path(&mut self, path_id: u32) -> Option<PathMetrics> {
        self.paths.remove(&path_id)
    }

    pub fn get_path(&self, path_id: u32) -> Option<&PathMetrics> {
        self.paths.get(&path_id)
    }

    pub fn get_path_mut(&mut self, path_id: u32) -> Option<&mut PathMetrics> {
        self.paths.get_mut(&path_id)
    }

    pub fn total_paths(&self) -> usize {
        self.paths.len()
    }

    pub fn active_paths(&self) -> Vec<u32> {
        self.paths
            .iter()
            .filter(|(_, p)| p.state == PathState::Active || p.state == PathState::Degraded)
            .map(|(&id, _)| id)
            .collect()
    }

    pub fn select_path_for_egress(&mut self) -> Option<u32> {
        let active: Vec<u32> = self.active_paths();
        if active.is_empty() {
            return None;
        }

        match self.mode {
            BondingMode::RoundRobin => {
                let idx = self.round_robin_counter % active.len();
                self.round_robin_counter = self.round_robin_counter.wrapping_add(1);
                Some(active[idx])
            }
            BondingMode::LowestLatency => {
                let mut best_id = active[0];
                let mut lowest_rtt = f64::MAX;

                for &id in &active {
                    if let Some(p) = self.paths.get(&id) {
                        if p.rtt_ms < lowest_rtt {
                            lowest_rtt = p.rtt_ms;
                            best_id = id;
                        }
                    }
                }
                Some(best_id)
            }
            BondingMode::WeightedLossRatio => {
                let mut best_id = active[0];
                let mut best_score = f64::MIN;

                for &id in &active {
                    if let Some(p) = self.paths.get(&id) {
                        let loss_penalty = (100.0 - p.loss_percentage).max(1.0);
                        let rtt_factor = (1000.0 / (p.rtt_ms.max(1.0))).min(100.0);
                        let score = (p.weight as f64) * loss_penalty * rtt_factor;
                        if score > best_score {
                            best_score = score;
                            best_id = id;
                        }
                    }
                }
                Some(best_id)
            }
            BondingMode::RedundantDuplicate => {
                Some(active[0])
            }
        }
    }

    pub fn encapsulate_payload(&mut self, path_id: u32, payload: &[u8]) -> Option<Vec<u8>> {
        if let Some(p) = self.paths.get_mut(&path_id) {
            p.tx_bytes += payload.len() as u64;

            let mut packet = Vec::with_capacity(7 + payload.len());
            packet.extend_from_slice(&path_id.to_be_bytes());
            packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            packet.push(0x01);
            packet.extend_from_slice(payload);
            Some(packet)
        } else {
            None
        }
    }

    pub fn decapsulate_payload(&mut self, raw_packet: &[u8]) -> Result<(u32, Vec<u8>), &'static str> {
        if raw_packet.len() < 7 {
            return Err("Packet too small for multipath frame header");
        }

        let path_id = u32::from_be_bytes([raw_packet[0], raw_packet[1], raw_packet[2], raw_packet[3]]);
        let payload_len = u16::from_be_bytes([raw_packet[4], raw_packet[5]]) as usize;
        let _flags = raw_packet[6];

        if raw_packet.len() < 7 + payload_len {
            return Err("Incomplete frame payload");
        }

        let payload = raw_packet[7..7 + payload_len].to_vec();
        if let Some(p) = self.paths.get_mut(&path_id) {
            p.rx_bytes += payload_len as u64;
        }

        Ok((path_id, payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multipath_tunnel_bonding() {
        let mut tunnel = MultipathUdpTunnel::new("tun-01", BondingMode::RoundRobin);
        let addr1: SocketAddr = "127.0.0.1:8001".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:8002".parse().unwrap();
        let remote: SocketAddr = "192.168.1.1:9000".parse().unwrap();

        tunnel.add_path(PathMetrics::new(1, addr1, remote, 10));
        tunnel.add_path(PathMetrics::new(2, addr2, remote, 20));

        assert_eq!(tunnel.total_paths(), 2);
        assert_eq!(tunnel.active_paths().len(), 2);

        let p1 = tunnel.select_path_for_egress().unwrap();
        let p2 = tunnel.select_path_for_egress().unwrap();
        assert_ne!(p1, p2);

        let payload = b"multipath payload test";
        let enc = tunnel.encapsulate_payload(1, payload).expect("encapsulate failed");
        assert!(enc.len() > payload.len());

        let (rx_path, dec) = tunnel.decapsulate_payload(&enc).expect("decapsulate failed");
        assert_eq!(rx_path, 1);
        assert_eq!(dec, payload);
    }

    #[test]
    fn test_lowest_latency_selection() {
        let mut tunnel = MultipathUdpTunnel::new("tun-02", BondingMode::LowestLatency);
        let addr1: SocketAddr = "127.0.0.1:8001".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:8002".parse().unwrap();
        let remote: SocketAddr = "192.168.1.1:9000".parse().unwrap();

        let mut path1 = PathMetrics::new(1, addr1, remote, 10);
        path1.record_heartbeat_reply(85.0, false);

        let mut path2 = PathMetrics::new(2, addr2, remote, 10);
        path2.record_heartbeat_reply(18.0, false);

        tunnel.add_path(path1);
        tunnel.add_path(path2);

        let chosen = tunnel.select_path_for_egress().unwrap();
        assert_eq!(chosen, 2);
    }
}
