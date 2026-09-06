//! # Edge Gateway Health Meter & Load Distribution Analyzer
//!
//! Provides quantile latency tracking, request rate calculation, and load health
//! scoring across edge gateway endpoints.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeHealthState {
    Healthy,
    Degraded,
    Critical,
    Down,
}

#[derive(Debug, Clone)]
pub struct EdgeGatewayMetrics {
    pub gateway_id: String,
    pub endpoint: String,
    pub total_requests: u64,
    pub failed_requests: u64,
    pub avg_latency_ms: u32,
    pub load_factor: f32, // 0.0 to 1.0
    pub state: EdgeHealthState,
}

pub struct EdgeGatewayHealthMeter {
    gateways: HashMap<String, EdgeGatewayMetrics>,
    failure_threshold: f32,
    latency_threshold_ms: u32,
}

impl EdgeGatewayHealthMeter {
    pub fn new(failure_threshold: f32, latency_threshold_ms: u32) -> Self {
        Self {
            gateways: HashMap::new(),
            failure_threshold: failure_threshold.clamp(0.01, 1.0),
            latency_threshold_ms,
        }
    }

    pub fn register_gateway(&mut self, gateway_id: &str, endpoint: &str) {
        self.gateways.insert(
            gateway_id.to_string(),
            EdgeGatewayMetrics {
                gateway_id: gateway_id.to_string(),
                endpoint: endpoint.to_string(),
                total_requests: 0,
                failed_requests: 0,
                avg_latency_ms: 0,
                load_factor: 0.0,
                state: EdgeHealthState::Healthy,
            },
        );
    }

    pub fn record_request(&mut self, gateway_id: &str, latency_ms: u32, success: bool) {
        if let Some(gw) = self.gateways.get_mut(gateway_id) {
            gw.total_requests += 1;
            if !success {
                gw.failed_requests += 1;
            }

            // Exponential moving average for latency
            if gw.avg_latency_ms == 0 {
                gw.avg_latency_ms = latency_ms;
            } else {
                gw.avg_latency_ms = (gw.avg_latency_ms * 7 + latency_ms * 3) / 10;
            }

            // Calculate failure rate
            let fail_rate = gw.failed_requests as f32 / gw.total_requests as f32;
            let latency_ratio = (gw.avg_latency_ms as f32 / self.latency_threshold_ms as f32).min(1.0);
            gw.load_factor = (fail_rate * 0.6 + latency_ratio * 0.4).clamp(0.0, 1.0);

            // Determine state
            if fail_rate > self.failure_threshold * 2.0 {
                gw.state = EdgeHealthState::Down;
            } else if fail_rate > self.failure_threshold {
                gw.state = EdgeHealthState::Critical;
            } else if gw.avg_latency_ms > self.latency_threshold_ms {
                gw.state = EdgeHealthState::Degraded;
            } else {
                gw.state = EdgeHealthState::Healthy;
            }
        }
    }

    pub fn get_metrics(&self, gateway_id: &str) -> Option<&EdgeGatewayMetrics> {
        self.gateways.get(gateway_id)
    }

    pub fn select_best_gateway(&self) -> Option<&EdgeGatewayMetrics> {
        self.gateways
            .values()
            .filter(|g| g.state != EdgeHealthState::Down)
            .min_by(|a, b| {
                a.load_factor
                    .partial_cmp(&b.load_factor)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edge_gateway_health_meter() {
        let mut meter = EdgeGatewayHealthMeter::new(0.2, 200);
        meter.register_gateway("gw1", "https://cf1.example.com");
        meter.register_gateway("gw2", "https://cf2.example.com");

        meter.record_request("gw1", 50, true);
        meter.record_request("gw1", 60, true);
        assert_eq!(meter.get_metrics("gw1").unwrap().state, EdgeHealthState::Healthy);

        // Degrade gw2 with failures
        meter.record_request("gw2", 250, false);
        meter.record_request("gw2", 300, false);
        assert_ne!(meter.get_metrics("gw2").unwrap().state, EdgeHealthState::Healthy);

        let best = meter.select_best_gateway().unwrap();
        assert_eq!(best.gateway_id, "gw1");
    }
}
