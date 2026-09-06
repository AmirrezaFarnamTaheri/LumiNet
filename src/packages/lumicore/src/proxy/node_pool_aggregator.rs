//! # Node Pool Aggregator
//!
//! Autonomous proxy node pool discovery, deduplication, scoring, and lifecycle aggregation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AggregatedNode {
    pub id: String,
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub score: f64,
    pub latency_ms: u32,
    pub success_count: u32,
    pub failure_count: u32,
    pub tags: Vec<String>,
    pub last_seen: u64,
}

pub struct NodePoolAggregator {
    nodes: HashMap<String, AggregatedNode>,
}

impl NodePoolAggregator {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    pub fn ingest_raw_entries(&mut self, entries: &[String], timestamp: u64) -> usize {
        let mut ingested = 0;
        for raw in entries {
            if let Some(node) = Self::parse_raw_line(raw, timestamp) {
                let key = format!("{}:{}:{}", node.protocol, node.host, node.port);
                self.nodes
                    .entry(key)
                    .and_modify(|n| {
                        n.last_seen = timestamp;
                        for tag in &node.tags {
                            if !n.tags.contains(tag) {
                                n.tags.push(tag.clone());
                            }
                        }
                    })
                    .or_insert(node);
                ingested += 1;
            }
        }
        ingested
    }

    pub fn update_health(&mut self, id: &str, latency_ms: u32, success: bool) -> bool {
        if let Some(node) = self.nodes.get_mut(id) {
            if success {
                node.success_count += 1;
                node.latency_ms = (node.latency_ms * 3 + latency_ms) / 4;
                let lat_score = (1000.0 / (node.latency_ms.max(10) as f64)).min(100.0);
                let reliability = node.success_count as f64 / (node.success_count + node.failure_count) as f64;
                node.score = (lat_score * 0.4) + (reliability * 60.0);
            } else {
                node.failure_count += 1;
                let reliability = node.success_count as f64 / (node.success_count + node.failure_count) as f64;
                node.score = node.score.min(reliability * 60.0);
            }
            true
        } else {
            false
        }
    }

    pub fn rank_nodes(&self, min_score: f64) -> Vec<AggregatedNode> {
        let mut list: Vec<_> = self
            .nodes
            .values()
            .filter(|n| n.score >= min_score)
            .cloned()
            .collect();
        list.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        list
    }

    pub fn export_pool_json(&self) -> String {
        serde_json::to_string_pretty(&self.nodes.values().collect::<Vec<_>>()).unwrap_or_default()
    }

    fn parse_raw_line(raw: &str, timestamp: u64) -> Option<AggregatedNode> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return None;
        }

        if let Some(idx) = trimmed.find("://") {
            let protocol = trimmed[..idx].to_lowercase();
            let remainder = &trimmed[idx + 3..];
            let parts: Vec<&str> = remainder.split('@').collect();
            let host_port = if parts.len() > 1 { parts[1] } else { parts[0] };
            let host_split: Vec<&str> = host_port.split(':').collect();
            if host_split.len() >= 2 {
                let host = host_split[0].to_string();
                let port_str = host_split[1].split(&['/', '?', '#'][..]).next().unwrap_or("0");
                let port = port_str.parse::<u16>().unwrap_or(443);
                let id = format!("{}:{}:{}", protocol, host, port);
                return Some(AggregatedNode {
                    id,
                    protocol,
                    host,
                    port,
                    score: 50.0,
                    latency_ms: 200,
                    success_count: 1,
                    failure_count: 0,
                    tags: vec!["public_pool".to_string()],
                    last_seen: timestamp,
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ingest_and_rank() {
        let mut aggregator = NodePoolAggregator::new();
        let lines = vec![
            "ss://aes-256-gcm:pass@node1.example.org:8388".to_string(),
            "trojan://secret@node2.example.org:443#Tokyo".to_string(),
            "invalid-scheme-line".to_string(),
        ];

        let count = aggregator.ingest_raw_entries(&lines, 1700000000);
        assert_eq!(count, 2);

        aggregator.update_health("trojan:node2.example.org:443", 30, true);
        aggregator.update_health("ss:node1.example.org:8388", 350, true);

        let ranked = aggregator.rank_nodes(40.0);
        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked[0].host, "node2.example.org");
    }
}
