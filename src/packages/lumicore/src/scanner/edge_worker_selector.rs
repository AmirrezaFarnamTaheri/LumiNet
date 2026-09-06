//! Edge Worker Endpoint Selector and Latency Rater
//!
//! Evaluates edge worker candidates against clean CDN IPs, computes combined
//! latency and packet loss metrics, and synthesizes optimal proxy configurations.

#[derive(Debug, Clone, PartialEq)]
pub struct WorkerEndpoint {
    pub domain: String,
    pub clean_ip: String,
    pub port: u16,
    pub latency_ms: u64,
    pub packet_loss_pct: f32,
}

impl WorkerEndpoint {
    /// Scoring metric: lower is better. Penalizes loss heavily.
    pub fn score(&self) -> f64 {
        (self.latency_ms as f64) + (self.packet_loss_pct as f64 * 150.0)
    }
}

#[derive(Debug, Default)]
pub struct EdgeWorkerSelector {
    endpoints: Vec<WorkerEndpoint>,
}

impl EdgeWorkerSelector {
    pub fn new() -> Self {
        Self { endpoints: Vec::new() }
    }

    pub fn add_or_update(&mut self, domain: &str, clean_ip: &str, port: u16, latency_ms: u64, loss: f32) {
        if let Some(ep) = self.endpoints.iter_mut().find(|e| e.domain == domain && e.clean_ip == clean_ip) {
            ep.latency_ms = latency_ms;
            ep.packet_loss_pct = loss;
            ep.port = port;
        } else {
            self.endpoints.push(WorkerEndpoint {
                domain: domain.to_string(),
                clean_ip: clean_ip.to_string(),
                port,
                latency_ms,
                packet_loss_pct: loss,
            });
        }
    }

    pub fn select_best(&self) -> Option<WorkerEndpoint> {
        self.endpoints
            .iter()
            .min_by(|a, b| a.score().partial_cmp(&b.score()).unwrap_or(std::cmp::Ordering::Equal))
            .cloned()
    }

    pub fn filter_candidates(&self, max_latency_ms: u64, max_loss_pct: f32) -> Vec<WorkerEndpoint> {
        let mut filtered: Vec<WorkerEndpoint> = self
            .endpoints
            .iter()
            .filter(|e| e.latency_ms <= max_latency_ms && e.packet_loss_pct <= max_loss_pct)
            .cloned()
            .collect();
        filtered.sort_by(|a, b| a.score().partial_cmp(&b.score()).unwrap_or(std::cmp::Ordering::Equal));
        filtered
    }

    pub fn synthesize_vless_uri(&self, ep: &WorkerEndpoint, uuid: &str, sni: &str) -> String {
        format!(
            "vless://{}@{}:{}?encryption=none&security=tls&sni={}&type=ws&host={}&path=%2F#LumiNet-Worker",
            uuid, ep.clean_ip, ep.port, sni, ep.domain
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selector_best() {
        let mut sel = EdgeWorkerSelector::new();
        sel.add_or_update("worker1.dev", "104.16.1.1", 443, 120, 0.0);
        sel.add_or_update("worker2.dev", "104.16.2.2", 443, 85, 2.0); // score = 85 + 300 = 385
        sel.add_or_update("worker3.dev", "104.16.3.3", 443, 90, 0.0); // score = 90

        let best = sel.select_best().unwrap();
        assert_eq!(best.clean_ip, "104.16.3.3");

        let uri = sel.synthesize_vless_uri(&best, "test-uuid", "worker3.dev");
        assert!(uri.contains("104.16.3.3:443"));
        assert!(uri.contains("test-uuid"));
    }
}
