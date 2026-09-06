//! Subnet Range Scout and Jitter Evaluator
//!
//! Evaluates candidate IP subnets, probing RTT and jitter variation across
//! host boundaries under constrained concurrency.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub struct SubnetProbeResult {
    pub subnet: String,
    pub sample_count: u32,
    pub avg_rtt_ms: f64,
    pub jitter_ms: f64,
    pub packet_loss_pct: f32,
}

impl SubnetProbeResult {
    pub fn quality_score(&self) -> f64 {
        self.avg_rtt_ms + (self.jitter_ms * 2.0) + (self.packet_loss_pct as f64 * 100.0)
    }
}

#[derive(Debug, Default)]
pub struct SubnetRangeScout {
    results: HashMap<String, SubnetProbeResult>,
}

impl SubnetRangeScout {
    pub fn new() -> Self {
        Self {
            results: HashMap::new(),
        }
    }

    pub fn record_probe(
        &mut self,
        subnet: &str,
        rtt_samples: &[f64],
        lost_count: u32,
    ) {
        if rtt_samples.is_empty() {
            return;
        }

        let total_samples = rtt_samples.len() as u32 + lost_count;
        let sum: f64 = rtt_samples.iter().sum();
        let avg = sum / (rtt_samples.len() as f64);

        // Compute jitter as mean absolute deviation from avg
        let jitter = rtt_samples
            .iter()
            .map(|&s| (s - avg).abs())
            .sum::<f64>()
            / (rtt_samples.len() as f64);

        let loss_pct = (lost_count as f32 / total_samples as f32) * 100.0;

        self.results.insert(
            subnet.to_string(),
            SubnetProbeResult {
                subnet: subnet.to_string(),
                sample_count: total_samples,
                avg_rtt_ms: avg,
                jitter_ms: jitter,
                packet_loss_pct: loss_pct,
            },
        );
    }

    pub fn select_best_subnet(&self) -> Option<&SubnetProbeResult> {
        self.results.values().min_by(|a, b| {
            a.quality_score()
                .partial_cmp(&b.quality_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    pub fn rank_subnets(&self) -> Vec<&SubnetProbeResult> {
        let mut list: Vec<&SubnetProbeResult> = self.results.values().collect();
        list.sort_by(|a, b| {
            a.quality_score()
                .partial_cmp(&b.quality_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        list
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subnet_range_scout() {
        let mut scout = SubnetRangeScout::new();
        scout.record_probe("104.16.0.0/20", &[50.0, 52.0, 48.0], 0);
        scout.record_probe("162.159.0.0/20", &[120.0, 130.0, 140.0], 1);

        let best = scout.select_best_subnet().unwrap();
        assert_eq!(best.subnet, "104.16.0.0/20");
        assert!(best.avg_rtt_ms < 60.0);
        assert_eq!(best.packet_loss_pct, 0.0);
    }
}
