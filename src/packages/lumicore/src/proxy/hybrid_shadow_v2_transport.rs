//! # Hybrid Shadow V2 Transport
//!
//! Dual-stack Shadowsocks and VMess/VLESS outbound transport dispatcher providing
//! transparent multiplexing, protocol negotiation, and failover route bridging.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HybridProtocolType {
    Shadowsocks,
    Vmess,
    Vless,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridEndpointConfig {
    pub endpoint_id: String,
    pub host: String,
    pub port: u16,
    pub protocol: HybridProtocolType,
    pub credentials_token: String,
    pub weight: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridOutboundStats {
    pub total_sessions: u64,
    pub active_sessions: u32,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub consecutive_errors: u32,
}

pub struct HybridShadowV2Transport {
    endpoints: HashMap<String, (HybridEndpointConfig, HybridOutboundStats)>,
    default_endpoint_id: Option<String>,
}

impl HybridShadowV2Transport {
    pub fn new() -> Self {
        Self {
            endpoints: HashMap::new(),
            default_endpoint_id: None,
        }
    }

    pub fn register_endpoint(&mut self, config: HybridEndpointConfig) {
        let id = config.endpoint_id.clone();
        if self.default_endpoint_id.is_none() {
            self.default_endpoint_id = Some(id.clone());
        }
        self.endpoints.insert(
            id,
            (
                config,
                HybridOutboundStats {
                    total_sessions: 0,
                    active_sessions: 0,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    consecutive_errors: 0,
                },
            ),
        );
    }

    pub fn select_outbound(&self) -> Option<&HybridEndpointConfig> {
        // Select healthy endpoint with highest weight
        let mut best: Option<(&HybridEndpointConfig, u32)> = None;

        for (cfg, stats) in self.endpoints.values() {
            if stats.consecutive_errors >= 3 {
                continue;
            }
            let effective_weight = cfg.weight / (stats.active_sessions.max(1));
            match best {
                None => best = Some((cfg, effective_weight)),
                Some((_, current_max)) if effective_weight > current_max => {
                    best = Some((cfg, effective_weight));
                }
                _ => {}
            }
        }

        if let Some((cfg, _)) = best {
            Some(cfg)
        } else if let Some(ref def_id) = self.default_endpoint_id {
            self.endpoints.get(def_id).map(|(cfg, _)| cfg)
        } else {
            None
        }
    }

    pub fn record_session_start(&mut self, endpoint_id: &str) {
        if let Some((_, stats)) = self.endpoints.get_mut(endpoint_id) {
            stats.total_sessions += 1;
            stats.active_sessions += 1;
        }
    }

    pub fn record_session_end(&mut self, endpoint_id: &str, rx: u64, tx: u64, success: bool) {
        if let Some((_, stats)) = self.endpoints.get_mut(endpoint_id) {
            stats.active_sessions = stats.active_sessions.saturating_sub(1);
            stats.rx_bytes += rx;
            stats.tx_bytes += tx;
            if success {
                stats.consecutive_errors = 0;
            } else {
                stats.consecutive_errors += 1;
            }
        }
    }

    pub fn get_stats(&self, endpoint_id: &str) -> Option<&HybridOutboundStats> {
        self.endpoints.get(endpoint_id).map(|(_, stats)| stats)
    }

    pub fn total_endpoints(&self) -> usize {
        self.endpoints.len()
    }
}

impl Default for HybridShadowV2Transport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_shadow_v2_dispatch() {
        let mut transport = HybridShadowV2Transport::new();

        let ss_cfg = HybridEndpointConfig {
            endpoint_id: "ss-east".to_string(),
            host: "198.51.100.1".to_string(),
            port: 8388,
            protocol: HybridProtocolType::Shadowsocks,
            credentials_token: "secret-aes-256-gcm".to_string(),
            weight: 50,
        };

        let vmess_cfg = HybridEndpointConfig {
            endpoint_id: "vmess-west".to_string(),
            host: "198.51.100.2".to_string(),
            port: 443,
            protocol: HybridProtocolType::Vmess,
            credentials_token: "a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
            weight: 100,
        };

        transport.register_endpoint(ss_cfg);
        transport.register_endpoint(vmess_cfg);

        // Initially, vmess-west has higher weight (100 > 50)
        let selected = transport.select_outbound().unwrap();
        assert_eq!(selected.endpoint_id, "vmess-west");

        // Start session on vmess-west
        transport.record_session_start("vmess-west");
        transport.record_session_end("vmess-west", 1024, 2048, true);
        let st = transport.get_stats("vmess-west").unwrap();
        assert_eq!(st.rx_bytes, 1024);
        assert_eq!(st.tx_bytes, 2048);

        // Inject consecutive errors on vmess-west to trigger failover
        transport.record_session_end("vmess-west", 0, 0, false);
        transport.record_session_end("vmess-west", 0, 0, false);
        transport.record_session_end("vmess-west", 0, 0, false);

        // After 3 errors, failover to ss-east
        let failover = transport.select_outbound().unwrap();
        assert_eq!(failover.endpoint_id, "ss-east");
    }
}
