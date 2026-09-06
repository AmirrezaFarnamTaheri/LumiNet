//! CIDR Subnet Neighbor Exploration Scanner
//!
//! Explores neighboring IP addresses around known-working CDN edge nodes,
//! probing TCP half-open SYN availability and measuring response latencies.

use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct ScannedNeighbor {
    pub ip: String,
    pub port: u16,
    pub rtt_ms: u64,
    pub available: bool,
}

#[derive(Debug, Default)]
pub struct SubnetNeighborScanner {
    neighbors: Vec<ScannedNeighbor>,
}

impl SubnetNeighborScanner {
    pub fn new() -> Self {
        Self {
            neighbors: Vec::new(),
        }
    }

    /// Generates candidate neighbor IPs in a range of +/- delta around a known IP
    pub fn generate_neighbor_candidates(center_ip: &str, delta: u8) -> Vec<String> {
        let ip: Ipv4Addr = match center_ip.parse() {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };

        let octets = ip.octets();
        let mut candidates = Vec::new();

        let start = octets[3].saturating_sub(delta);
        let end = octets[3].saturating_add(delta);

        for last in start..=end {
            if last != octets[3] && last != 0 && last != 255 {
                candidates.push(format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], last));
            }
        }
        candidates
    }

    pub fn record_result(&mut self, ip: &str, port: u16, rtt_ms: u64, available: bool) {
        self.neighbors.push(ScannedNeighbor {
            ip: ip.to_string(),
            port,
            rtt_ms,
            available,
        });
    }

    pub fn available_neighbors(&self) -> Vec<ScannedNeighbor> {
        let mut avail: Vec<ScannedNeighbor> = self.neighbors.iter().filter(|n| n.available).cloned().collect();
        avail.sort_by_key(|n| n.rtt_ms);
        avail
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_neighbor_candidates_and_ranking() {
        let candidates = SubnetNeighborScanner::generate_neighbor_candidates("104.16.1.10", 2);
        assert_eq!(candidates.len(), 4); // 8, 9, 11, 12
        assert!(candidates.contains(&"104.16.1.8".to_string()));
        assert!(candidates.contains(&"104.16.1.12".to_string()));

        let mut scanner = SubnetNeighborScanner::new();
        scanner.record_result("104.16.1.8", 443, 60, true);
        scanner.record_result("104.16.1.9", 443, 999, false);
        scanner.record_result("104.16.1.11", 443, 45, true);

        let avail = scanner.available_neighbors();
        assert_eq!(avail.len(), 2);
        assert_eq!(avail[0].ip, "104.16.1.11"); // Lower RTT first
    }
}
