//! # Multicarrier Relay Channel
//!
//! Multi-carrier anti-censorship relay channel manager with dynamic carrier failover,
//! route health scoring, and weighted route selection across heterogeneous networks.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CarrierType {
    Telecom,
    Unicom,
    Mobile,
    Satellite,
    OverlayRelay,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarrierRoute {
    pub carrier: CarrierType,
    pub endpoint: String,
    pub latency_ms: u32,
    pub packet_loss: f32,
    pub weight: u32,
    pub is_active: bool,
    pub consecutive_failures: u32,
}

pub struct MulticarrierRelayChannel {
    routes: Vec<CarrierRoute>,
    carrier_stats: HashMap<CarrierType, (u64, u64)>, // (successes, attempts)
}

impl MulticarrierRelayChannel {
    pub fn new() -> Self {
        Self {
            routes: Vec::new(),
            carrier_stats: HashMap::new(),
        }
    }

    pub fn add_route(&mut self, route: CarrierRoute) {
        self.routes.push(route);
    }

    pub fn select_best_carrier(&self) -> Option<CarrierRoute> {
        let mut active_routes: Vec<_> = self.routes.iter().filter(|r| r.is_active).collect();
        if active_routes.is_empty() {
            return None;
        }

        // Score: weight / (latency_ms * (1.0 + packet_loss * 5.0) * (1.0 + consecutive_failures))
        active_routes.sort_by(|a, b| {
            let score_a = self.calculate_score(a);
            let score_b = self.calculate_score(b);
            score_b.partial_cmp(&score_a).unwrap_or(std::cmp::Ordering::Equal)
        });

        Some(active_routes[0].clone())
    }

    pub fn failover_sequence(&self) -> Vec<CarrierRoute> {
        let mut sorted = self.routes.clone();
        sorted.sort_by(|a, b| {
            let score_a = self.calculate_score(a);
            let score_b = self.calculate_score(b);
            score_b.partial_cmp(&score_a).unwrap_or(std::cmp::Ordering::Equal)
        });
        sorted
    }

    pub fn record_feedback(&mut self, carrier: CarrierType, rtt_ms: u32, success: bool) {
        let entry = self.carrier_stats.entry(carrier).or_insert((0, 0));
        entry.1 += 1;
        if success {
            entry.0 += 1;
        }

        for r in &mut self.routes {
            if r.carrier == carrier {
                if success {
                    r.consecutive_failures = 0;
                    r.latency_ms = (r.latency_ms * 3 + rtt_ms) / 4;
                    r.packet_loss = r.packet_loss * 0.8;
                    r.is_active = true;
                } else {
                    r.consecutive_failures += 1;
                    r.packet_loss = (r.packet_loss * 0.8) + 0.2;
                    if r.consecutive_failures >= 3 {
                        r.is_active = false;
                    }
                }
            }
        }
    }

    fn calculate_score(&self, route: &CarrierRoute) -> f64 {
        let lat = route.latency_ms.max(1) as f64;
        let loss = route.packet_loss as f64;
        let fails = route.consecutive_failures as f64;
        let base_weight = route.weight as f64;

        base_weight / (lat * (1.0 + loss * 5.0) * (1.0 + fails * 2.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multicarrier_selection_and_failover() {
        let mut channel = MulticarrierRelayChannel::new();
        channel.add_route(CarrierRoute {
            carrier: CarrierType::Telecom,
            endpoint: "1.1.1.1:443".to_string(),
            latency_ms: 100,
            packet_loss: 0.05,
            weight: 100,
            is_active: true,
            consecutive_failures: 0,
        });
        channel.add_route(CarrierRoute {
            carrier: CarrierType::Unicom,
            endpoint: "2.2.2.2:443".to_string(),
            latency_ms: 40,
            packet_loss: 0.01,
            weight: 100,
            is_active: true,
            consecutive_failures: 0,
        });

        // Unicom should be best due to lower latency
        let best = channel.select_best_carrier().unwrap();
        assert_eq!(best.carrier, CarrierType::Unicom);

        // Fail Unicom 3 times
        channel.record_feedback(CarrierType::Unicom, 999, false);
        channel.record_feedback(CarrierType::Unicom, 999, false);
        channel.record_feedback(CarrierType::Unicom, 999, false);

        // Now Telecom should be best
        let failover = channel.select_best_carrier().unwrap();
        assert_eq!(failover.carrier, CarrierType::Telecom);
    }
}
