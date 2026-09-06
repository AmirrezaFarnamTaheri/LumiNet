//! # Multipath Transport Latency Ranker & Fallback Router
//!
//! Evaluates multiple circumvention tiers (Direct QUIC, Obfuscated Brook/Hysteria,
//! Domain Fronting, SSL-VPN) and executes rapid graceful degradation on blockades.

use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransportTier {
    Tier1DirectQuic = 1,
    Tier2ObfuscatedUdp = 2,
    Tier3DomainFronted = 3,
    Tier4SslVpnFallback = 4,
}

#[derive(Debug, Clone)]
pub struct TierState {
    pub tier: TransportTier,
    pub consecutive_errors: u32,
    pub rtt_ms: u32,
    pub last_success: Option<Instant>,
    pub disabled_until: Option<Instant>,
}

pub struct MultipathFallbackRouter {
    states: Vec<TierState>,
    max_consecutive_errors: u32,
    backoff_duration: Duration,
}

impl MultipathFallbackRouter {
    pub fn new(max_consecutive_errors: u32, backoff_duration: Duration) -> Self {
        let tiers = vec![
            TransportTier::Tier1DirectQuic,
            TransportTier::Tier2ObfuscatedUdp,
            TransportTier::Tier3DomainFronted,
            TransportTier::Tier4SslVpnFallback,
        ];
        let states = tiers
            .into_iter()
            .map(|tier| TierState {
                tier,
                consecutive_errors: 0,
                rtt_ms: 100 * (tier as u32),
                last_success: None,
                disabled_until: None,
            })
            .collect();

        Self {
            states,
            max_consecutive_errors,
            backoff_duration,
        }
    }

    pub fn select_active_tier(&self) -> TransportTier {
        let now = Instant::now();
        for state in &self.states {
            if let Some(until) = state.disabled_until {
                if now < until {
                    continue;
                }
            }
            return state.tier;
        }
        // If all are backed off, default to deepest fallback
        TransportTier::Tier4SslVpnFallback
    }

    pub fn record_tier_success(&mut self, tier: TransportTier, rtt: Duration) {
        if let Some(state) = self.states.iter_mut().find(|s| s.tier == tier) {
            state.consecutive_errors = 0;
            state.last_success = Some(Instant::now());
            state.disabled_until = None;
            state.rtt_ms = rtt.as_millis() as u32;
        }
    }

    pub fn record_tier_failure(&mut self, tier: TransportTier) {
        if let Some(state) = self.states.iter_mut().find(|s| s.tier == tier) {
            state.consecutive_errors += 1;
            if state.consecutive_errors >= self.max_consecutive_errors {
                state.disabled_until = Some(Instant::now() + self.backoff_duration);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multipath_fallback_degradation() {
        let mut router = MultipathFallbackRouter::new(2, Duration::from_secs(60));
        assert_eq!(router.select_active_tier(), TransportTier::Tier1DirectQuic);

        // Fail Tier 1 twice
        router.record_tier_failure(TransportTier::Tier1DirectQuic);
        assert_eq!(router.select_active_tier(), TransportTier::Tier1DirectQuic);
        router.record_tier_failure(TransportTier::Tier1DirectQuic);

        // Should fall back to Tier 2
        assert_eq!(router.select_active_tier(), TransportTier::Tier2ObfuscatedUdp);

        // Recover Tier 1
        router.record_tier_success(TransportTier::Tier1DirectQuic, Duration::from_millis(45));
        assert_eq!(router.select_active_tier(), TransportTier::Tier1DirectQuic);
    }
}
