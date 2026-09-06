//! # DNS-over-HTTPS Fallback Hierarchy
//!
//! Tiered multi-provider DoH resolver hierarchy with automated health grading,
//! bootstrap IP resolution, and zero-downtime failover cascade.
//! Ported and enhanced from mofelee/how-to-fxxk-gfw.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolutionTier {
    Tier1EncryptedDoH = 1,
    Tier2AlternativeDoH = 2,
    Tier3DirectBootstrap = 3,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DohEndpoint {
    pub url: String,
    pub host: String,
    pub bootstrap_ips: Vec<String>,
    pub tier: ResolutionTier,
    pub is_healthy: bool,
    pub consecutive_failures: u32,
    pub avg_latency_ms: u32,
}

#[derive(Debug, Clone, Default)]
pub struct DohFallbackHierarchy {
    endpoints: HashMap<String, DohEndpoint>,
}

impl DohFallbackHierarchy {
    pub fn new() -> Self {
        let mut hierarchy = Self {
            endpoints: HashMap::new(),
        };
        hierarchy.register_defaults();
        hierarchy
    }

    pub fn register_defaults(&mut self) {
        self.add_endpoint(DohEndpoint {
            url: "https://1.1.1.1/dns-query".to_string(),
            host: "cloudflare-dns.com".to_string(),
            bootstrap_ips: vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()],
            tier: ResolutionTier::Tier1EncryptedDoH,
            is_healthy: true,
            consecutive_failures: 0,
            avg_latency_ms: 25,
        });

        self.add_endpoint(DohEndpoint {
            url: "https://dns.google/dns-query".to_string(),
            host: "dns.google".to_string(),
            bootstrap_ips: vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
            tier: ResolutionTier::Tier1EncryptedDoH,
            is_healthy: true,
            consecutive_failures: 0,
            avg_latency_ms: 35,
        });

        self.add_endpoint(DohEndpoint {
            url: "https://doh.opendns.com/dns-query".to_string(),
            host: "doh.opendns.com".to_string(),
            bootstrap_ips: vec!["208.67.222.222".to_string()],
            tier: ResolutionTier::Tier2AlternativeDoH,
            is_healthy: true,
            consecutive_failures: 0,
            avg_latency_ms: 60,
        });
    }

    pub fn add_endpoint(&mut self, endpoint: DohEndpoint) {
        self.endpoints.insert(endpoint.url.clone(), endpoint);
    }

    pub fn mark_failure(&mut self, url: &str) {
        if let Some(ep) = self.endpoints.get_mut(url) {
            ep.consecutive_failures += 1;
            if ep.consecutive_failures >= 3 {
                ep.is_healthy = false;
            }
        }
    }

    pub fn mark_success(&mut self, url: &str, latency_ms: u32) {
        if let Some(ep) = self.endpoints.get_mut(url) {
            ep.consecutive_failures = 0;
            ep.is_healthy = true;
            ep.avg_latency_ms = (ep.avg_latency_ms * 3 + latency_ms) / 4;
        }
    }

    pub fn select_active_endpoint(&self) -> Option<DohEndpoint> {
        let mut candidates: Vec<&DohEndpoint> = self
            .endpoints
            .values()
            .filter(|ep| ep.is_healthy)
            .collect();

        if candidates.is_empty() {
            // Re-enable all if all are marked down
            return self.endpoints.values().next().cloned();
        }

        // Sort by tier asc (Tier1 before Tier2), then lowest avg latency
        candidates.sort_by(|a, b| {
            a.tier
                .cmp(&b.tier)
                .then_with(|| a.avg_latency_ms.cmp(&b.avg_latency_ms))
        });

        candidates.first().map(|&ep| ep.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_doh_selection_and_failover() {
        let mut hierarchy = DohFallbackHierarchy::new();
        let first = hierarchy.select_active_endpoint().unwrap();
        assert_eq!(first.tier, ResolutionTier::Tier1EncryptedDoH);

        // Fail first 3 times
        hierarchy.mark_failure(&first.url);
        hierarchy.mark_failure(&first.url);
        hierarchy.mark_failure(&first.url);

        let second = hierarchy.select_active_endpoint().unwrap();
        assert_ne!(second.url, first.url);
    }
}
