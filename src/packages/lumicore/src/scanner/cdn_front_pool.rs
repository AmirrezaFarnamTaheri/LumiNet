//! # CDN Fronting Pool & Latency Ranker
//!
//! Provides a resilient IP pool manager with dynamic TLS handshake latency scoring,
//! circuit-breaker quarantine for failing endpoints, and healthy round-robin candidate rotation.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub struct CdnCandidate {
    pub ip: IpAddr,
    pub sni_host: String,
    pub port: u16,
    pub rtt_ms: u32,
    pub success_count: u32,
    pub failure_count: u32,
    pub consecutive_failures: u32,
    pub quarantined_until: Option<Instant>,
}

#[derive(Debug, Clone)]
pub struct CdnFrontPoolConfig {
    pub max_consecutive_failures: u32,
    pub quarantine_duration: Duration,
    pub max_rtt_threshold_ms: u32,
}

impl Default for CdnFrontPoolConfig {
    fn default() -> Self {
        Self {
            max_consecutive_failures: 3,
            quarantine_duration: Duration::from_secs(60),
            max_rtt_threshold_ms: 1500,
        }
    }
}

pub struct CdnFrontPool {
    config: CdnFrontPoolConfig,
    candidates: HashMap<IpAddr, CdnCandidate>,
    round_robin_index: usize,
}

impl CdnFrontPool {
    pub fn new(config: CdnFrontPoolConfig) -> Self {
        Self {
            config,
            candidates: HashMap::new(),
            round_robin_index: 0,
        }
    }

    pub fn add_candidate(&mut self, ip: IpAddr, sni_host: String, port: u16) {
        self.candidates.entry(ip).or_insert(CdnCandidate {
            ip,
            sni_host,
            port,
            rtt_ms: 9999,
            success_count: 0,
            failure_count: 0,
            consecutive_failures: 0,
            quarantined_until: None,
        });
    }

    pub fn record_success(&mut self, ip: &IpAddr, rtt: Duration) {
        if let Some(candidate) = self.candidates.get_mut(ip) {
            candidate.success_count += 1;
            candidate.consecutive_failures = 0;
            candidate.quarantined_until = None;
            let new_rtt = rtt.as_millis() as u32;
            if candidate.rtt_ms == 9999 {
                candidate.rtt_ms = new_rtt;
            } else {
                // Exponential moving average: 0.7 * old + 0.3 * new
                candidate.rtt_ms = ((candidate.rtt_ms as f32 * 0.7) + (new_rtt as f32 * 0.3)) as u32;
            }
        }
    }

    pub fn record_failure(&mut self, ip: &IpAddr) {
        if let Some(candidate) = self.candidates.get_mut(ip) {
            candidate.failure_count += 1;
            candidate.consecutive_failures += 1;
            if candidate.consecutive_failures >= self.config.max_consecutive_failures {
                candidate.quarantined_until = Some(Instant::now() + self.config.quarantine_duration);
            }
        }
    }

    pub fn get_healthy_candidates(&self) -> Vec<CdnCandidate> {
        let now = Instant::now();
        let mut healthy: Vec<CdnCandidate> = self
            .candidates
            .values()
            .filter(|c| {
                if let Some(until) = c.quarantined_until {
                    if now < until {
                        return false;
                    }
                }
                c.rtt_ms <= self.config.max_rtt_threshold_ms
            })
            .cloned()
            .collect();

        healthy.sort_by_key(|c| c.rtt_ms);
        healthy
    }

    pub fn pick_next_candidate(&mut self) -> Option<CdnCandidate> {
        let healthy = self.get_healthy_candidates();
        if healthy.is_empty() {
            return None;
        }
        let cand = healthy[self.round_robin_index % healthy.len()].clone();
        self.round_robin_index = (self.round_robin_index + 1) % healthy.len();
        Some(cand)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_cdn_front_pool_lifecycle() {
        let mut pool = CdnFrontPool::new(CdnFrontPoolConfig::default());
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));

        pool.add_candidate(ip1, "cdn.example.com".to_string(), 443);
        pool.add_candidate(ip2, "cdn.example.com".to_string(), 443);

        pool.record_success(&ip1, Duration::from_millis(50));
        pool.record_success(&ip2, Duration::from_millis(200));

        let healthy = pool.get_healthy_candidates();
        assert_eq!(healthy.len(), 2);
        assert_eq!(healthy[0].ip, ip1); // lowest RTT first

        // Trigger quarantine on ip1
        pool.record_failure(&ip1);
        pool.record_failure(&ip1);
        pool.record_failure(&ip1);

        let healthy_after = pool.get_healthy_candidates();
        assert_eq!(healthy_after.len(), 1);
        assert_eq!(healthy_after[0].ip, ip2);
    }
}
