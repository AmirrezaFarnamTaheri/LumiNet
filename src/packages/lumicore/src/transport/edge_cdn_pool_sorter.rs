//! # Edge CDN IP Pool Latency Sorter
//!
//! Evaluates candidate CDN edge IPs by recorded latency and packet success rates,
//! allowing dynamic selection of fastest reachable edge nodes.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct EdgeIpRecord {
    pub ip_address: String,
    pub latency_ms: u32,
    pub packet_loss_ratio: f32,
    pub is_available: bool,
}

pub struct EdgeCdnPoolSorter {
    ip_pool: HashMap<String, EdgeIpRecord>,
    max_latency_threshold: u32,
}

impl EdgeCdnPoolSorter {
    pub fn new(max_latency_threshold: u32) -> Self {
        Self {
            ip_pool: HashMap::new(),
            max_latency_threshold,
        }
    }

    pub fn add_ip(&mut self, ip: &str) {
        self.ip_pool.insert(
            ip.to_string(),
            EdgeIpRecord {
                ip_address: ip.to_string(),
                latency_ms: u32::MAX,
                packet_loss_ratio: 1.0,
                is_available: false,
            },
        );
    }

    pub fn update_probe_result(&mut self, ip: &str, latency_ms: u32, success: bool) {
        if let Some(entry) = self.ip_pool.get_mut(ip) {
            if success {
                entry.latency_ms = latency_ms;
                entry.packet_loss_ratio = 0.0;
                entry.is_available = latency_ms <= self.max_latency_threshold;
            } else {
                entry.packet_loss_ratio = 1.0;
                entry.is_available = false;
            }
        }
    }

    pub fn get_sorted_fastest(&self) -> Vec<EdgeIpRecord> {
        let mut available: Vec<EdgeIpRecord> = self
            .ip_pool
            .values()
            .filter(|r| r.is_available)
            .cloned()
            .collect();
        available.sort_by_key(|r| r.latency_ms);
        available
    }

    pub fn best_ip(&self) -> Option<String> {
        self.get_sorted_fastest().first().map(|r| r.ip_address.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edge_cdn_pool_sorter() {
        let mut sorter = EdgeCdnPoolSorter::new(300);
        sorter.add_ip("142.250.190.46");
        sorter.add_ip("172.217.16.206");
        sorter.add_ip("216.58.214.206");

        sorter.update_probe_result("142.250.190.46", 120, true);
        sorter.update_probe_result("172.217.16.206", 45, true);
        sorter.update_probe_result("216.58.214.206", 450, true); // exceeds threshold

        assert_eq!(sorter.best_ip(), Some("172.217.16.206".to_string()));
        let sorted = sorter.get_sorted_fastest();
        assert_eq!(sorted.len(), 2);
        assert_eq!(sorted[0].latency_ms, 45);
        assert_eq!(sorted[1].latency_ms, 120);
    }
}
