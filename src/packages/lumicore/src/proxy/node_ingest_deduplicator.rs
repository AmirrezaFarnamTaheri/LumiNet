//! # Automated Node Ingest Deduplicator
//!
//! Aggregates, normalizes, deduplicates, and health-ranks proxy node manifests
//! scraped from heterogeneous public and private sources.

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeEndpointKey {
    pub host: String,
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone)]
pub struct ScrapedNode {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub source: String,
    pub ping_ms: u32,
    pub is_alive: bool,
}

pub struct NodeIngestDeduplicator {
    seen_endpoints: HashSet<NodeEndpointKey>,
    unique_nodes: Vec<ScrapedNode>,
    source_stats: HashMap<String, usize>,
}

impl NodeIngestDeduplicator {
    pub fn new() -> Self {
        Self {
            seen_endpoints: HashSet::new(),
            unique_nodes: Vec::new(),
            source_stats: HashMap::new(),
        }
    }

    pub fn ingest_node(&mut self, node: ScrapedNode) -> bool {
        let key = NodeEndpointKey {
            host: node.host.trim().to_lowercase(),
            port: node.port,
            protocol: node.protocol.trim().to_lowercase(),
        };

        if self.seen_endpoints.insert(key) {
            *self.source_stats.entry(node.source.clone()).or_insert(0) += 1;
            self.unique_nodes.push(node);
            true
        } else {
            false // duplicate
        }
    }

    pub fn get_ranked_nodes(&self) -> Vec<ScrapedNode> {
        let mut alive: Vec<ScrapedNode> = self.unique_nodes.iter().filter(|n| n.is_alive).cloned().collect();
        alive.sort_by_key(|n| n.ping_ms);
        alive
    }

    pub fn total_unique(&self) -> usize {
        self.unique_nodes.len()
    }

    pub fn count_for_source(&self, source: &str) -> usize {
        self.source_stats.get(source).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_deduplication_and_ranking() {
        let mut dedup = NodeIngestDeduplicator::new();

        let n1 = ScrapedNode {
            host: "node1.net".to_string(),
            port: 443,
            protocol: "trojan".to_string(),
            source: "feed_a".to_string(),
            ping_ms: 150,
            is_alive: true,
        };

        let n2 = ScrapedNode {
            host: "NODE1.NET".to_string(), // duplicate case-insensitive
            port: 443,
            protocol: "trojan".to_string(),
            source: "feed_b".to_string(),
            ping_ms: 180,
            is_alive: true,
        };

        let n3 = ScrapedNode {
            host: "node2.net".to_string(),
            port: 8443,
            protocol: "vmess".to_string(),
            source: "feed_a".to_string(),
            ping_ms: 60,
            is_alive: true,
        };

        assert!(dedup.ingest_node(n1));
        assert!(!dedup.ingest_node(n2)); // rejected as duplicate
        assert!(dedup.ingest_node(n3));

        assert_eq!(dedup.total_unique(), 2);
        assert_eq!(dedup.count_for_source("feed_a"), 2);
        assert_eq!(dedup.count_for_source("feed_b"), 0);

        let ranked = dedup.get_ranked_nodes();
        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked[0].host, "node2.net"); // lowest ping
        assert_eq!(ranked[1].host, "node1.net");
    }
}
