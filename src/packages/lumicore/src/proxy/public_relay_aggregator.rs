//! # Public Relay Aggregator
//!
//! Scrapes, cleanses, and classifies community proxy relay nodes published in
//! markdown tables, plaintext lists, and YAML registries with geo-tag extraction.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicRelayNode {
    pub node_id: String,
    pub address: String,
    pub port: u16,
    pub protocol: String,
    pub country_code: String,
    pub speed_mbps: f32,
    pub last_checked: u64,
}

pub struct PublicRelayAggregator {
    nodes: HashMap<String, PublicRelayNode>,
}

impl PublicRelayAggregator {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    pub fn ingest_markdown_table(&mut self, table_content: &str, timestamp: u64) -> usize {
        let mut count = 0;

        for line in table_content.lines() {
            let trimmed = line.trim();
            if !trimmed.starts_with('|') || trimmed.contains("---") || trimmed.to_lowercase().contains("address") {
                continue;
            }

            let cols: Vec<&str> = trimmed
                .split('|')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();

            if cols.len() >= 4 {
                // Expected format: | Address | Port | Protocol | Country | [Speed] |
                let address = cols[0].to_string();
                let port = cols[1].parse::<u16>().unwrap_or(0);
                let protocol = cols[2].to_lowercase();
                let country = cols[3].to_uppercase();
                let speed = if cols.len() > 4 {
                    cols[4].trim_end_matches("Mbps").trim().parse::<f32>().unwrap_or(10.0)
                } else {
                    10.0
                };

                if port > 0 && !address.is_empty() {
                    let node_id = format!("{}:{}:{}", protocol, address, port);
                    self.nodes.insert(
                        node_id.clone(),
                        PublicRelayNode {
                            node_id,
                            address,
                            port,
                            protocol,
                            country_code: country,
                            speed_mbps: speed,
                            last_checked: timestamp,
                        },
                    );
                    count += 1;
                }
            }
        }

        count
    }

    pub fn filter_by_country(&self, country: &str) -> Vec<&PublicRelayNode> {
        let cc = country.to_uppercase();
        self.nodes
            .values()
            .filter(|n| n.country_code == cc)
            .collect()
    }

    pub fn get_fastest_nodes(&self, limit: usize) -> Vec<&PublicRelayNode> {
        let mut list: Vec<&PublicRelayNode> = self.nodes.values().collect();
        list.sort_by(|a, b| b.speed_mbps.partial_cmp(&a.speed_mbps).unwrap_or(std::cmp::Ordering::Equal));
        list.into_iter().take(limit).collect()
    }

    pub fn total_relays(&self) -> usize {
        self.nodes.len()
    }
}

impl Default for PublicRelayAggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_relay_ingestion_and_filters() {
        let mut agg = PublicRelayAggregator::new();

        let md = r#"
| Address | Port | Protocol | Country | Speed |
|---|---|---|---|---|
| 192.0.2.1 | 443 | trojan | US | 100 Mbps |
| 198.51.100.2 | 8443 | vless | JP | 250 Mbps |
| 203.0.113.3 | 80 | vmess | US | 50 Mbps |
"#;

        let ingested = agg.ingest_markdown_table(md, 1000);
        assert_eq!(ingested, 3);
        assert_eq!(agg.total_relays(), 3);

        let us_nodes = agg.filter_by_country("US");
        assert_eq!(us_nodes.len(), 2);

        let fastest = agg.get_fastest_nodes(2);
        assert_eq!(fastest.len(), 2);
        assert_eq!(fastest[0].country_code, "JP");
        assert_eq!(fastest[0].speed_mbps, 250.0);
    }
}
