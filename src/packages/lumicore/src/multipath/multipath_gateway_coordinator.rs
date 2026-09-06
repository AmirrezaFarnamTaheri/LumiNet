//! Multipath Gateway Coordinator
//!
//! Recomposes multiple upstream tunnel paths, performs in-order deduplication,
//! and distributes traffic over healthy multi-link bonded egresses.

use crate::multipath::multipath_dedup_buffer::MultipathDedupBuffer;
use crate::relay::weighted_egress_router::WeightedEgressRouter;

#[derive(Debug)]
pub struct MultipathGatewayCoordinator {
    pub dedup: MultipathDedupBuffer,
    pub router: WeightedEgressRouter,
}

impl MultipathGatewayCoordinator {
    pub fn new(initial_seq: u64, max_history: usize) -> Self {
        Self {
            dedup: MultipathDedupBuffer::new(initial_seq, max_history),
            router: WeightedEgressRouter::new(),
        }
    }

    pub fn register_uplink(&mut self, id: &str, endpoint: &str, weight: u32) {
        self.router.add_route(id, endpoint, weight);
    }

    pub fn set_uplink_health(&mut self, id: &str, healthy: bool) {
        self.router.set_health(id, healthy);
    }

    pub fn dispatch_next_uplink(&mut self) -> Option<String> {
        self.router.next_route()
    }

    pub fn ingest_incoming_packet(&mut self, seq: u64, data: Vec<u8>) -> Option<Vec<Vec<u8>>> {
        self.dedup.ingest(seq, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gateway_coordinator() {
        let mut coord = MultipathGatewayCoordinator::new(1, 100);
        coord.register_uplink("link-1", "10.0.0.1:443", 2);
        coord.register_uplink("link-2", "10.0.0.2:443", 1);

        assert_eq!(coord.dispatch_next_uplink().unwrap(), "10.0.0.1:443");

        // Test dedup integration
        assert!(coord.ingest_incoming_packet(2, b"p2".to_vec()).is_none());
        let ready = coord.ingest_incoming_packet(1, b"p1".to_vec()).unwrap();
        assert_eq!(ready.len(), 2);
    }
}
