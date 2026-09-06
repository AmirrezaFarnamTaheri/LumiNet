//! # Multiproto Egress Selector
//!
//! Dynamic multi-protocol egress routing engine supporting VMess, VLESS, Shadowsocks,
//! and SSTP with automated fallback chains, protocol preference scoring, and health gating.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EgressProtocol {
    Vmess,
    Vless,
    Shadowsocks,
    Sstp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressEndpoint {
    pub id: String,
    pub protocol: EgressProtocol,
    pub address: String,
    pub port: u16,
    pub priority: u32,
    pub is_available: bool,
    pub latency_ms: u32,
}

pub struct MultiprotoEgressSelector {
    endpoints: HashMap<String, EgressEndpoint>,
    protocol_order: Vec<EgressProtocol>,
}

impl MultiprotoEgressSelector {
    pub fn new(protocol_order: Vec<EgressProtocol>) -> Self {
        Self {
            endpoints: HashMap::new(),
            protocol_order: if protocol_order.is_empty() {
                vec![
                    EgressProtocol::Vless,
                    EgressProtocol::Vmess,
                    EgressProtocol::Shadowsocks,
                    EgressProtocol::Sstp,
                ]
            } else {
                protocol_order
            },
        }
    }

    pub fn add_endpoint(&mut self, endpoint: EgressEndpoint) {
        self.endpoints.insert(endpoint.id.clone(), endpoint);
    }

    pub fn set_endpoint_health(&mut self, id: &str, is_available: bool, latency_ms: u32) {
        if let Some(ep) = self.endpoints.get_mut(id) {
            ep.is_available = is_available;
            ep.latency_ms = latency_ms;
        }
    }

    pub fn select_best_egress(&self) -> Option<&EgressEndpoint> {
        for proto in &self.protocol_order {
            let mut candidates: Vec<&EgressEndpoint> = self
                .endpoints
                .values()
                .filter(|ep| ep.protocol == *proto && ep.is_available)
                .collect();

            if !candidates.is_empty() {
                // Pick lowest latency within the highest preferred protocol tier
                candidates.sort_by_key(|ep| (ep.priority, ep.latency_ms));
                return Some(candidates[0]);
            }
        }

        // Ultimate fallback: any available endpoint
        self.endpoints.values().find(|ep| ep.is_available)
    }

    pub fn total_endpoints(&self) -> usize {
        self.endpoints.len()
    }
}

impl Default for MultiprotoEgressSelector {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multiproto_egress_selection_and_fallback() {
        let mut selector = MultiprotoEgressSelector::new(vec![
            EgressProtocol::Vless,
            EgressProtocol::Vmess,
            EgressProtocol::Shadowsocks,
        ]);

        let vless_node = EgressEndpoint {
            id: "vless-1".to_string(),
            protocol: EgressProtocol::Vless,
            address: "vless.node.net".to_string(),
            port: 443,
            priority: 1,
            is_available: true,
            latency_ms: 120,
        };

        let ss_node = EgressEndpoint {
            id: "ss-1".to_string(),
            protocol: EgressProtocol::Shadowsocks,
            address: "ss.node.net".to_string(),
            port: 8388,
            priority: 1,
            is_available: true,
            latency_ms: 40,
        };

        selector.add_endpoint(vless_node);
        selector.add_endpoint(ss_node);

        // Even though ss-1 has lower latency, VLESS is preferred in protocol order!
        let chosen = selector.select_best_egress().unwrap();
        assert_eq!(chosen.id, "vless-1");

        // Mark VLESS as unavailable -> automatic fallback to Shadowsocks!
        selector.set_endpoint_health("vless-1", false, 999);
        let fallback = selector.select_best_egress().unwrap();
        assert_eq!(fallback.id, "ss-1");
    }
}
