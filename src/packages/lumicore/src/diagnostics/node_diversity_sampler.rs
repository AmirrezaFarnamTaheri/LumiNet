//! # Node Diversity Sampler
//!
//! Evaluates the geographical, Autonomous System Number (ASN), and subnet diversity
//! of active node pools to avoid single-AS/single-cloud correlated blocking risks.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiversityNodeDescriptor {
    pub node_id: String,
    pub asn: u32,
    pub country_code: String,
    pub ip_prefix_24: String,
    pub latency_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiversityMetrics {
    pub total_nodes: usize,
    pub unique_asns: usize,
    pub unique_countries: usize,
    pub asn_entropy: f64,
    pub diversity_score: f64,
}

pub struct NodeDiversitySampler {
    nodes: HashMap<String, DiversityNodeDescriptor>,
}

impl NodeDiversitySampler {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, node: DiversityNodeDescriptor) {
        self.nodes.insert(node.node_id.clone(), node);
    }

    pub fn compute_diversity_metrics(&self) -> DiversityMetrics {
        if self.nodes.is_empty() {
            return DiversityMetrics {
                total_nodes: 0,
                unique_asns: 0,
                unique_countries: 0,
                asn_entropy: 0.0,
                diversity_score: 0.0,
            };
        }

        let mut asn_counts: HashMap<u32, usize> = HashMap::new();
        let mut country_counts: HashMap<String, usize> = HashMap::new();

        for node in self.nodes.values() {
            *asn_counts.entry(node.asn).or_insert(0) += 1;
            *country_counts.entry(node.country_code.clone()).or_insert(0) += 1;
        }

        let total = self.nodes.len() as f64;
        let mut entropy = 0.0;
        for &count in asn_counts.values() {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }

        // Diversity score normalized 0.0 to 100.0 based on entropy and country spread
        let max_entropy = total.log2().max(1.0);
        let normalized_entropy = (entropy / max_entropy).min(1.0);
        let country_factor = (country_counts.len() as f64 / total.max(1.0)).min(1.0);
        let diversity_score = (normalized_entropy * 60.0 + country_factor * 40.0).min(100.0);

        DiversityMetrics {
            total_nodes: self.nodes.len(),
            unique_asns: asn_counts.len(),
            unique_countries: country_counts.len(),
            asn_entropy: entropy,
            diversity_score,
        }
    }

    pub fn sample_diverse_subset(&self, max_nodes: usize) -> Vec<String> {
        let mut asn_seen: HashMap<u32, usize> = HashMap::new();
        let mut sorted_nodes: Vec<&DiversityNodeDescriptor> = self.nodes.values().collect();
        // Prefer lower latency
        sorted_nodes.sort_by_key(|n| n.latency_ms);

        let mut sampled = Vec::new();

        // Pass 1: One per ASN
        for node in &sorted_nodes {
            if sampled.len() >= max_nodes {
                break;
            }
            if !asn_seen.contains_key(&node.asn) {
                asn_seen.insert(node.asn, 1);
                sampled.push(node.node_id.clone());
            }
        }

        // Pass 2: Fill remaining up to max_nodes
        for node in &sorted_nodes {
            if sampled.len() >= max_nodes {
                break;
            }
            if !sampled.contains(&node.node_id) {
                sampled.push(node.node_id.clone());
            }
        }

        sampled
    }
}

impl Default for NodeDiversitySampler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_diversity_sampler() {
        let mut sampler = NodeDiversitySampler::new();

        sampler.add_node(DiversityNodeDescriptor {
            node_id: "node-cloudflare-us".to_string(),
            asn: 13335,
            country_code: "US".to_string(),
            ip_prefix_24: "104.16.1.0".to_string(),
            latency_ms: 20,
        });

        sampler.add_node(DiversityNodeDescriptor {
            node_id: "node-cloudflare-de".to_string(),
            asn: 13335,
            country_code: "DE".to_string(),
            ip_prefix_24: "104.16.2.0".to_string(),
            latency_ms: 35,
        });

        sampler.add_node(DiversityNodeDescriptor {
            node_id: "node-aws-jp".to_string(),
            asn: 16509,
            country_code: "JP".to_string(),
            ip_prefix_24: "13.230.1.0".to_string(),
            latency_ms: 80,
        });

        let metrics = sampler.compute_diversity_metrics();
        assert_eq!(metrics.total_nodes, 3);
        assert_eq!(metrics.unique_asns, 2);
        assert_eq!(metrics.unique_countries, 3);
        assert!(metrics.diversity_score > 50.0);

        let sampled = sampler.sample_diverse_subset(2);
        assert_eq!(sampled.len(), 2);
        // Sampled must pick from different ASNs in Pass 1!
        assert!(sampled.contains(&"node-cloudflare-us".to_string()));
        assert!(sampled.contains(&"node-aws-jp".to_string()));
    }
}
