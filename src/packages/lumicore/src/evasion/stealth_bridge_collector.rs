// Pure Rust implementation: Tor Pluggable Transport Stealth Bridge Collector

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluggableTransportType {
    Obfs4,
    Snowflake,
    WebTunnel,
    Meek,
    Custom(String),
}

#[derive(Debug, Clone)]
pub struct StealthBridge {
    pub transport: PluggableTransportType,
    pub endpoint: String,
    pub fingerprint: String,
    pub params: HashMap<String, String>,
    pub score: f64,
    pub latency_ms: u32,
    pub verified: bool,
}

pub struct StealthBridgeCollector {
    pub bridges: Vec<StealthBridge>,
    pub min_score_threshold: f64,
}

impl StealthBridgeCollector {
    pub fn new(min_score_threshold: f64) -> Self {
        Self {
            bridges: Vec::new(),
            min_score_threshold,
        }
    }

    pub fn parse_bridge_line(&mut self, line: &str) -> Result<StealthBridge, String> {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return Err("Empty or commented line".to_string());
        }

        // Typical format:
        // obfs4 192.0.2.1:443 7325514E91D3B62042C026C1F740E7DF98E2A180 cert=... iat-mode=0
        // or:
        // webtunnel 192.0.2.1:443 7325514E91D3B62042C026C1F740E7DF98E2A180 url=https://...
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 3 {
            return Err("Bridge line contains insufficient tokens".to_string());
        }

        let transport = match parts[0].to_ascii_lowercase().as_str() {
            "obfs4" => PluggableTransportType::Obfs4,
            "snowflake" => PluggableTransportType::Snowflake,
            "webtunnel" => PluggableTransportType::WebTunnel,
            "meek" => PluggableTransportType::Meek,
            other => PluggableTransportType::Custom(other.to_string()),
        };

        let endpoint = parts[1].to_string();
        let fingerprint = parts[2].to_uppercase();

        let mut params = HashMap::new();
        for token in &parts[3..] {
            if let Some((k, v)) = token.split_once('=') {
                params.insert(k.to_string(), v.to_string());
            }
        }

        let bridge = StealthBridge {
            transport,
            endpoint,
            fingerprint,
            params,
            score: 1.0,
            latency_ms: 0,
            verified: false,
        };

        self.bridges.push(bridge.clone());
        Ok(bridge)
    }

    pub fn record_health(&mut self, fingerprint: &str, latency_ms: u32, success: bool) -> bool {
        let upper_fp = fingerprint.to_uppercase();
        if let Some(b) = self.bridges.iter_mut().find(|b| b.fingerprint == upper_fp) {
            if success {
                b.verified = true;
                b.latency_ms = latency_ms;
                // Latency reward: sub-200ms scores higher
                let latency_factor = (1000.0 / (latency_ms.max(50) as f64)).min(2.0);
                b.score = (b.score * 0.8) + (1.2 * latency_factor);
            } else {
                b.score *= 0.5; // Penalize failed connection
                if b.score < 0.1 {
                    b.verified = false;
                }
            }
            true
        } else {
            false
        }
    }

    pub fn get_best_bridges(&self, transport: Option<PluggableTransportType>, limit: usize) -> Vec<StealthBridge> {
        let mut matching: Vec<StealthBridge> = self
            .bridges
            .iter()
            .filter(|b| {
                if let Some(ref t) = transport {
                    &b.transport == t
                } else {
                    true
                }
            })
            .filter(|b| b.score >= self.min_score_threshold)
            .cloned()
            .collect();

        matching.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        matching.truncate(limit);
        matching
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_obfs4_and_webtunnel() {
        let mut collector = StealthBridgeCollector::new(0.5);

        let obfs4_line = "obfs4 192.0.2.1:443 7325514E91D3B62042C026C1F740E7DF98E2A180 cert=qPMIiat/7J iat-mode=0";
        let b1 = collector.parse_bridge_line(obfs4_line).unwrap();
        assert_eq!(b1.transport, PluggableTransportType::Obfs4);
        assert_eq!(b1.params.get("cert"), Some(&"qPMIiat/7J".to_string()));
        assert_eq!(b1.params.get("iat-mode"), Some(&"0".to_string()));

        let webtunnel_line = "webtunnel 198.51.100.5:443 9A8B7C6D5E4F3A2B1C0D url=https://cdn.example.com/tunnel";
        let b2 = collector.parse_bridge_line(webtunnel_line).unwrap();
        assert_eq!(b2.transport, PluggableTransportType::WebTunnel);
        assert_eq!(b2.params.get("url"), Some(&"https://cdn.example.com/tunnel".to_string()));
    }

    #[test]
    fn test_record_health_and_ranking() {
        let mut collector = StealthBridgeCollector::new(0.5);
        collector.parse_bridge_line("obfs4 1.1.1.1:443 AAAAA cert=1").unwrap();
        collector.parse_bridge_line("obfs4 2.2.2.2:443 BBBBB cert=2").unwrap();

        collector.record_health("AAAAA", 120, true);
        collector.record_health("BBBBB", 800, false);

        let best = collector.get_best_bridges(Some(PluggableTransportType::Obfs4), 1);
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].fingerprint, "AAAAA");
    }
}
