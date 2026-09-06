//! # Adaptive Outbound Resilience Coordinator (Convergence Pass 1)
//!
//! Synthesizes Multi-Outbound routing (94), Provider Failover Watcher (95),
//! Camouflage Stream Masquerader (99), and Edge CDN Pool Sorter (101) into an
//! autonomous high-availability outbound egress controller.

use crate::diagnostics::provider_failover_watcher::ProviderFailoverWatcher;
use crate::routing::multi_outbound_router::{MultiOutboundRouter, OutboundPolicy};
use crate::transport::camouflage_stream_masquerader::{CamouflageStreamMasquerader, ProbeAction};
use crate::transport::edge_cdn_pool_sorter::EdgeCdnPoolSorter;

pub struct AdaptiveOutboundResilienceCoordinator {
    pub router: MultiOutboundRouter,
    pub watcher: ProviderFailoverWatcher,
    pub masquerader: CamouflageStreamMasquerader,
    pub cdn_sorter: EdgeCdnPoolSorter,
    pub total_dispatched: u64,
}

impl AdaptiveOutboundResilienceCoordinator {
    pub fn new(
        default_policy: OutboundPolicy,
        failover_threshold: u32,
        shared_secret: &[u8],
        decoy_host: &str,
        max_cdn_latency: u32,
    ) -> Self {
        Self {
            router: MultiOutboundRouter::new(default_policy),
            watcher: ProviderFailoverWatcher::new(failover_threshold),
            masquerader: CamouflageStreamMasquerader::new(shared_secret, decoy_host),
            cdn_sorter: EdgeCdnPoolSorter::new(max_cdn_latency),
            total_dispatched: 0,
        }
    }

    pub fn route_and_prepare_outbound(
        &mut self,
        target_domain: &str,
        user_id: [u8; 16],
    ) -> (OutboundPolicy, Option<String>, Vec<u8>) {
        self.total_dispatched += 1;

        // 1. Determine policy via multi outbound router
        let policy = self.router.match_target(target_domain);

        // 2. Resolve best CDN egress IP if applicable
        let best_ip = self.cdn_sorter.best_ip();

        // 3. Generate obfuscated session preamble for camouflage transport
        let preamble = self.masquerader.generate_preamble(user_id);

        (policy, best_ip, preamble)
    }

    pub fn handle_inbound_probe(&self, preamble: &[u8]) -> ProbeAction {
        self.masquerader.inspect_inbound_stream(preamble)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adaptive_outbound_coordinator() {
        let mut coord = AdaptiveOutboundResilienceCoordinator::new(
            OutboundPolicy::Direct,
            3,
            b"secret-key-1234",
            "www.cloudflare.com",
            200,
        );

        coord.router.add_rule("blocked.org", true, OutboundPolicy::Proxy("proxy-us".to_string()));
        coord.cdn_sorter.add_ip("104.16.1.1");
        coord.cdn_sorter.update_probe_result("104.16.1.1", 35, true);

        let uid = [0x77; 16];
        coord.masquerader.register_user(uid);

        let (policy, ip, preamble) = coord.route_and_prepare_outbound("sub.blocked.org", uid);
        assert_eq!(policy, OutboundPolicy::Proxy("proxy-us".to_string()));
        assert_eq!(ip, Some("104.16.1.1".to_string()));
        assert_eq!(coord.handle_inbound_probe(&preamble), ProbeAction::AcceptStream);
    }
}
