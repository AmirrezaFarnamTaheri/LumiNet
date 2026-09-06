//! # PAC Subscription Orchestrator (Synthesis C2)
//!
//! Master orchestrator unifying proxy subscription harvesting, node pool aggregation,
//! health tier ranking, dynamic PAC rule compilation, and synchronized differential deployment.

use crate::diagnostics::subscription_health_classifier::{HealthTier, SubscriptionHealthClassifier};
use crate::proxy::node_pool_aggregator::NodePoolAggregator;
use crate::proxy::subscription_crawler_pipeline::SubscriptionCrawlerPipeline;
use crate::routing::pac_diff_synchronizer::{PacDiffSynchronizer, PacSyncDelta};
use crate::routing::pac_rule_generator::{PacAction, PacRuleGenerator};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestratorSummary {
    pub total_crawled: usize,
    pub total_active_pool: usize,
    pub usable_tier_a_count: usize,
    pub current_pac_rules_count: usize,
    pub pac_checksum: String,
}

pub struct PacSubscriptionOrchestrator {
    crawler: SubscriptionCrawlerPipeline,
    pool: NodePoolAggregator,
    classifier: SubscriptionHealthClassifier,
    pac_gen: PacRuleGenerator,
    pac_sync: PacDiffSynchronizer,
    default_proxy_port: u16,
}

impl PacSubscriptionOrchestrator {
    pub fn new(initial_domains: &[String], default_proxy_port: u16) -> Self {
        let mut pac_gen = PacRuleGenerator::new(PacAction::Direct);
        for d in initial_domains {
            pac_gen.add_rule(d, PacAction::Proxy(format!("127.0.0.1:{}", default_proxy_port)));
        }

        Self {
            crawler: SubscriptionCrawlerPipeline::new(),
            pool: NodePoolAggregator::new(),
            classifier: SubscriptionHealthClassifier::new(10),
            pac_gen,
            pac_sync: PacDiffSynchronizer::new(initial_domains),
            default_proxy_port,
        }
    }

    pub fn register_subscription_source(&mut self, url: &str, interval_secs: u64) {
        self.crawler.add_source(url, interval_secs);
    }

    pub fn execute_crawl_and_ingest(&mut self, source_url: &str, raw_content: &str, now: u64) -> usize {
        let count = self.crawler.ingest_crawl_content(source_url, raw_content);
        let proxies = self.crawler.get_harvested_proxies();
        self.pool.ingest_raw_entries(&proxies, now);
        count
    }

    pub fn record_node_probe(&mut self, node_id: &str, latency_ms: u32, success: bool) {
        self.classifier.record_sample(node_id, latency_ms, success);
        self.pool.update_health(node_id, latency_ms, success);
    }

    pub fn update_pac_with_upstream(&mut self, upstream_domains: &[String]) -> Result<PacSyncDelta, String> {
        let delta = self.pac_sync.compute_delta(upstream_domains);
        self.pac_sync.apply_delta(&delta)?;

        // Rebuild pac_gen
        self.pac_gen = PacRuleGenerator::new(PacAction::Direct);
        for domain in upstream_domains {
            self.pac_gen.add_rule(
                domain,
                PacAction::Proxy(format!("127.0.0.1:{}", self.default_proxy_port)),
            );
        }

        Ok(delta)
    }

    pub fn export_active_pac_script(&self) -> String {
        self.pac_gen.generate_pac_script()
    }

    pub fn get_summary(&self) -> OrchestratorSummary {
        let tier_a = self.classifier.filter_usable_nodes(HealthTier::TierAExcellent);
        OrchestratorSummary {
            total_crawled: self.crawler.total_harvested_count(),
            total_active_pool: self.pool.rank_nodes(0.0).len(),
            usable_tier_a_count: tier_a.len(),
            current_pac_rules_count: self.pac_sync.total_rules(),
            pac_checksum: self.pac_sync.current_checksum(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pac_subscription_orchestrator() {
        let base_domains = vec!["youtube.com".to_string(), "netflix.com".to_string()];
        let mut orch = PacSubscriptionOrchestrator::new(&base_domains, 10808);

        orch.register_subscription_source("https://subs.org/free", 3600);
        let payload = "trojan://pass@fast.edge.io:443#FastNode\nss://method:pass@slow.edge.io:8388";
        let harvested = orch.execute_crawl_and_ingest("https://subs.org/free", payload, 1000);
        assert_eq!(harvested, 2);

        // Probe nodes
        for _ in 0..5 {
            orch.record_node_probe("trojan:fast.edge.io:443", 35, true);
            orch.record_node_probe("ss:slow.edge.io:8388", 450, true);
        }

        let summary = orch.get_summary();
        assert_eq!(summary.total_crawled, 2);
        assert_eq!(summary.total_active_pool, 2);
        assert_eq!(summary.usable_tier_a_count, 1);
        assert_eq!(summary.current_pac_rules_count, 2);

        // Update upstream PAC
        let upstream = vec![
            "youtube.com".to_string(),
            "netflix.com".to_string(),
            "wikipedia.org".to_string(),
        ];
        let delta = orch.update_pac_with_upstream(&upstream).unwrap();
        assert_eq!(delta.added_domains, vec!["wikipedia.org".to_string()]);

        let script = orch.export_active_pac_script();
        assert!(script.contains("wikipedia.org"));
        assert!(script.contains("127.0.0.1:10808"));
    }
}
