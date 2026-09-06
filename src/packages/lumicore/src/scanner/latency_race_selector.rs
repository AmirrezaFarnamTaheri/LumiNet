use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub struct OutboundNode {
    pub node_id: String,
    pub protocol: String,
    pub endpoint: String,
    pub ewma_latency_ms: f64,
    pub total_probes: u64,
}

#[derive(Debug, Default)]
pub struct LatencyRaceSelector {
    nodes: HashMap<String, OutboundNode>,
}

impl LatencyRaceSelector {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    pub fn register_node(&mut self, id: &str, protocol: &str, endpoint: &str) {
        self.nodes.insert(id.to_string(), OutboundNode {
            node_id: id.to_string(),
            protocol: protocol.to_string(),
            endpoint: endpoint.to_string(),
            ewma_latency_ms: 0.0,
            total_probes: 0,
        });
    }

    pub fn record_probe(&mut self, id: &str, latency_ms: f64) {
        if let Some(node) = self.nodes.get_mut(id) {
            node.total_probes += 1;
            if node.ewma_latency_ms == 0.0 {
                node.ewma_latency_ms = latency_ms;
            } else {
                node.ewma_latency_ms = 0.7 * node.ewma_latency_ms + 0.3 * latency_ms;
            }
        }
    }

    pub fn select_fastest(&self) -> Option<&OutboundNode> {
        self.nodes.values()
            .filter(|n| n.ewma_latency_ms > 0.0)
            .min_by(|a, b| a.ewma_latency_ms.partial_cmp(&b.ewma_latency_ms).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_race_selection() {
        let mut racer = LatencyRaceSelector::new();
        racer.register_node("node1", "vless", "1.1.1.1:443");
        racer.register_node("node2", "shadowsocks", "2.2.2.2:443");

        racer.record_probe("node1", 120.0);
        racer.record_probe("node2", 45.0);

        let fastest = racer.select_fastest().expect("should find fastest");
        assert_eq!(fastest.node_id, "node2");
        assert_eq!(fastest.ewma_latency_ms, 45.0);
    }
}
