//! # Subscription Health Classifier
//!
//! Live subscription node stream validator measuring RTT, packet loss, and jitter,
//! classifying nodes into operational health tiers (Tier A through Tier F).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HealthTier {
    TierFDead = 0,
    TierCDegraded = 1,
    TierBGood = 2,
    TierAExcellent = 3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHealthReport {
    pub node_id: String,
    pub tier: HealthTier,
    pub avg_rtt_ms: u32,
    pub jitter_ms: u32,
    pub packet_loss: f32,
    pub total_probes: u32,
}

#[derive(Debug, Clone)]
struct NodeProbeStats {
    samples: Vec<u32>,
    failures: u32,
    total: u32,
}

pub struct SubscriptionHealthClassifier {
    nodes: HashMap<String, NodeProbeStats>,
    max_samples_per_node: usize,
}

impl SubscriptionHealthClassifier {
    pub fn new(max_samples_per_node: usize) -> Self {
        Self {
            nodes: HashMap::new(),
            max_samples_per_node: max_samples_per_node.max(5),
        }
    }

    pub fn record_sample(&mut self, node_id: &str, rtt_ms: u32, success: bool) {
        let stats = self
            .nodes
            .entry(node_id.to_string())
            .or_insert_with(|| NodeProbeStats {
                samples: Vec::new(),
                failures: 0,
                total: 0,
            });

        stats.total += 1;
        if success {
            stats.samples.push(rtt_ms);
            if stats.samples.len() > self.max_samples_per_node {
                stats.samples.remove(0);
            }
        } else {
            stats.failures += 1;
        }
    }

    pub fn classify_node(&self, node_id: &str) -> HealthTier {
        let stats = match self.nodes.get(node_id) {
            Some(s) => s,
            None => return HealthTier::TierFDead,
        };

        if stats.samples.is_empty() {
            return HealthTier::TierFDead;
        }

        let loss = stats.failures as f32 / stats.total as f32;
        let avg_rtt = stats.samples.iter().sum::<u32>() / stats.samples.len() as u32;

        if loss <= 0.05 && avg_rtt <= 80 {
            HealthTier::TierAExcellent
        } else if loss <= 0.15 && avg_rtt <= 200 {
            HealthTier::TierBGood
        } else if loss <= 0.40 && avg_rtt <= 600 {
            HealthTier::TierCDegraded
        } else {
            HealthTier::TierFDead
        }
    }

    pub fn generate_report(&self, node_id: &str) -> Option<NodeHealthReport> {
        let stats = self.nodes.get(node_id)?;
        if stats.samples.is_empty() {
            return Some(NodeHealthReport {
                node_id: node_id.to_string(),
                tier: HealthTier::TierFDead,
                avg_rtt_ms: 0,
                jitter_ms: 0,
                packet_loss: 1.0,
                total_probes: stats.total,
            });
        }

        let avg_rtt = stats.samples.iter().sum::<u32>() / stats.samples.len() as u32;
        let mut jitter = 0;
        for w in stats.samples.windows(2) {
            let diff = if w[0] > w[1] { w[0] - w[1] } else { w[1] - w[0] };
            jitter += diff;
        }
        if stats.samples.len() > 1 {
            jitter /= (stats.samples.len() - 1) as u32;
        }

        let loss = stats.failures as f32 / stats.total as f32;
        let tier = self.classify_node(node_id);

        Some(NodeHealthReport {
            node_id: node_id.to_string(),
            tier,
            avg_rtt_ms: avg_rtt,
            jitter_ms: jitter,
            packet_loss: loss,
            total_probes: stats.total,
        })
    }

    pub fn filter_usable_nodes(&self, min_tier: HealthTier) -> Vec<String> {
        self.nodes
            .keys()
            .filter(|id| self.classify_node(id) >= min_tier)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subscription_classifier_tiers() {
        let mut classifier = SubscriptionHealthClassifier::new(10);

        // Node 1: Fast and 0% loss
        for _ in 0..10 {
            classifier.record_sample("node-fast", 45, true);
        }
        assert_eq!(classifier.classify_node("node-fast"), HealthTier::TierAExcellent);

        // Node 2: 120ms with occasional loss
        for i in 0..10 {
            classifier.record_sample("node-med", 120, i != 2);
        }
        assert_eq!(classifier.classify_node("node-med"), HealthTier::TierBGood);

        // Node 3: Dead
        for _ in 0..5 {
            classifier.record_sample("node-dead", 999, false);
        }
        assert_eq!(classifier.classify_node("node-dead"), HealthTier::TierFDead);

        let usable = classifier.filter_usable_nodes(HealthTier::TierBGood);
        assert!(usable.contains(&"node-fast".to_string()));
        assert!(usable.contains(&"node-med".to_string()));
        assert!(!usable.contains(&"node-dead".to_string()));
    }
}
