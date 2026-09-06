//! # Decentralized P2P Mesh Routing & Metric Evaluator
//!
//! Distance-vector route calculation with composite link cost:
//! Cost = RTT_ms * 0.7 + LossRate * 350.0 + HopCount * 15.0

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq)]
pub struct PeerLinkMetric {
    pub rtt_ms: f32,
    pub loss_rate: f32, // 0.0 .. 1.0
    pub hop_count: u32,
}

impl PeerLinkMetric {
    pub fn compute_cost(&self) -> f32 {
        (self.rtt_ms * 0.7) + (self.loss_rate * 350.0) + (self.hop_count as f32 * 15.0)
    }
}

#[derive(Debug, Clone)]
pub struct MeshRouteEntry {
    pub destination_node: String,
    pub next_hop_addr: IpAddr,
    pub metric: PeerLinkMetric,
    pub cost: f32,
    pub last_updated: Instant,
}

pub struct MeshPeerTable {
    routes: HashMap<String, MeshRouteEntry>,
}

impl MeshPeerTable {
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
        }
    }

    pub fn update_route(
        &mut self,
        destination_node: String,
        next_hop_addr: IpAddr,
        metric: PeerLinkMetric,
    ) -> bool {
        let cost = metric.compute_cost();
        let entry = MeshRouteEntry {
            destination_node: destination_node.clone(),
            next_hop_addr,
            metric,
            cost,
            last_updated: Instant::now(),
        };

        if let Some(existing) = self.routes.get(&destination_node) {
            if cost < existing.cost {
                self.routes.insert(destination_node, entry);
                return true;
            }
            false
        } else {
            self.routes.insert(destination_node, entry);
            true
        }
    }

    pub fn lookup_route(&self, destination_node: &str) -> Option<&MeshRouteEntry> {
        self.routes.get(destination_node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_mesh_peer_route_cost_selection() {
        let mut table = MeshPeerTable::new();
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 10, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 10, 0, 2));

        // Route 1: higher latency (100ms), 0 loss
        let m1 = PeerLinkMetric { rtt_ms: 100.0, loss_rate: 0.0, hop_count: 1 };
        // Route 2: lower latency (30ms), 0 loss
        let m2 = PeerLinkMetric { rtt_ms: 30.0, loss_rate: 0.0, hop_count: 1 };

        table.update_route("node-b".to_string(), ip1, m1);
        assert_eq!(table.lookup_route("node-b").unwrap().next_hop_addr, ip1);

        // Lower cost update should replace existing
        let updated = table.update_route("node-b".to_string(), ip2, m2);
        assert!(updated);
        assert_eq!(table.lookup_route("node-b").unwrap().next_hop_addr, ip2);
    }
}
