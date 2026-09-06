//! Smooth Weighted Round-Robin (SWRR) Egress Tunnel Router
//!
//! Dispatches outbound flows across multiple upstream relays according to
//! assigned weights, tracking current effective weights and health status.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct EgressRoute {
    pub id: String,
    pub endpoint: String,
    pub weight: i32,
    pub current_weight: i32,
    pub healthy: bool,
}

#[derive(Debug, Default)]
pub struct WeightedEgressRouter {
    routes: Vec<EgressRoute>,
}

impl WeightedEgressRouter {
    pub fn new() -> Self {
        Self { routes: Vec::new() }
    }

    pub fn add_route(&mut self, id: &str, endpoint: &str, weight: u32) {
        self.routes.push(EgressRoute {
            id: id.to_string(),
            endpoint: endpoint.to_string(),
            weight: weight as i32,
            current_weight: 0,
            healthy: true,
        });
    }

    pub fn set_health(&mut self, id: &str, healthy: bool) {
        if let Some(r) = self.routes.iter_mut().find(|r| r.id == id) {
            r.healthy = healthy;
            if !healthy {
                r.current_weight = 0;
            }
        }
    }

    /// Selects the next route using NGINX-style Smooth Weighted Round Robin
    pub fn next_route(&mut self) -> Option<String> {
        let total_healthy_weight: i32 = self
            .routes
            .iter()
            .filter(|r| r.healthy && r.weight > 0)
            .map(|r| r.weight)
            .sum();

        if total_healthy_weight <= 0 {
            return None;
        }

        let mut best_idx: Option<usize> = None;
        let mut max_weight = i32::MIN;

        for (i, r) in self.routes.iter_mut().enumerate() {
            if !r.healthy || r.weight <= 0 {
                continue;
            }
            r.current_weight += r.weight;
            if r.current_weight > max_weight {
                max_weight = r.current_weight;
                best_idx = Some(i);
            }
        }

        if let Some(idx) = best_idx {
            self.routes[idx].current_weight -= total_healthy_weight;
            Some(self.routes[idx].endpoint.clone())
        } else {
            None
        }
    }

    pub fn route_count(&self) -> usize {
        self.routes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smooth_weighted_round_robin() {
        let mut router = WeightedEgressRouter::new();
        router.add_route("r1", "10.0.0.1:443", 5);
        router.add_route("r2", "10.0.0.2:443", 1);

        let mut r1_count = 0;
        let mut r2_count = 0;

        for _ in 0..6 {
            let ep = router.next_route().unwrap();
            if ep == "10.0.0.1:443" {
                r1_count += 1;
            } else if ep == "10.0.0.2:443" {
                r2_count += 1;
            }
        }

        assert_eq!(r1_count, 5);
        assert_eq!(r2_count, 1);
    }

    #[test]
    fn test_unhealthy_route_skipped() {
        let mut router = WeightedEgressRouter::new();
        router.add_route("r1", "10.0.0.1:443", 10);
        router.add_route("r2", "10.0.0.2:443", 10);
        router.set_health("r1", false);

        for _ in 0..5 {
            assert_eq!(router.next_route().unwrap(), "10.0.0.2:443");
        }
    }
}
