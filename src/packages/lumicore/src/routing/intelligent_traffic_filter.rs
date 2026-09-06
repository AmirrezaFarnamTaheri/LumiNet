//! Second-Order Convergence: Intelligent Traffic Filter
//!
//! Unifies DNS blocklisting, canonical rule evaluation, geospatial geo-fence routing,
//! and flow DPI telemetry into an integrated connection policy decision engine.

use std::net::SocketAddr;
use crate::dns::dns_blocklist_engine::{BlockCategory, DnsBlocklistEngine};
use crate::routing::canonical_blacklist_engine::{CanonicalBlacklistEngine, MatchResult};
use crate::routing::geospatial_polygon_router::{GeoPoint, GeospatialPolygonRouter};
use crate::diagnostics::flow_analyzer_engine::{FlowAnalyzerEngine, IdentifiedProtocol};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterVerdict {
    BlockedDns(BlockCategory),
    ProxyRequired { rule_hit: String, egress_tag: String },
    DirectPassThrough { egress_tag: String },
}

pub struct IntelligentTrafficFilter {
    pub dns_blocklist: DnsBlocklistEngine,
    pub canonical_rules: CanonicalBlacklistEngine,
    pub geo_router: GeospatialPolygonRouter,
    pub flow_analyzer: FlowAnalyzerEngine,
    total_evaluated_queries: u64,
}

impl IntelligentTrafficFilter {
    pub fn new(default_egress: impl Into<String>) -> Self {
        Self {
            dns_blocklist: DnsBlocklistEngine::new(),
            canonical_rules: CanonicalBlacklistEngine::new(),
            geo_router: GeospatialPolygonRouter::new(default_egress),
            flow_analyzer: FlowAnalyzerEngine::new(),
            total_evaluated_queries: 0,
        }
    }

    pub fn evaluate_traffic(
        &mut self,
        src: SocketAddr,
        dst: SocketAddr,
        domain: Option<&str>,
        user_location: Option<&GeoPoint>,
        initial_payload: &[u8],
    ) -> FilterVerdict {
        self.total_evaluated_queries += 1;

        // 1. Flow registration & protocol classification
        let _fid = self.flow_analyzer.register_flow(src, dst, initial_payload);

        // 2. DNS Blocklist Check (ad/malware/tracker)
        if let Some(d) = domain {
            if let Some(cat) = self.dns_blocklist.is_domain_blocked(d) {
                return FilterVerdict::BlockedDns(cat);
            }
        }

        // 3. Resolve egress from user spatial coordinates
        let (spatial_egress, _region) = match user_location {
            Some(loc) => self.geo_router.resolve_egress_for_coordinates(loc),
            None => ("default-direct".to_string(), None),
        };

        // 4. Blacklist / Bypass Check
        if let Some(d) = domain {
            match self.canonical_rules.evaluate_target(d) {
                MatchResult::Blocked(rule) => FilterVerdict::ProxyRequired {
                    rule_hit: rule,
                    egress_tag: "tunnel-proxy".to_string(),
                },
                MatchResult::Whitelisted(_) => FilterVerdict::DirectPassThrough {
                    egress_tag: spatial_egress,
                },
                MatchResult::DefaultDirect => FilterVerdict::DirectPassThrough {
                    egress_tag: spatial_egress,
                },
            }
        } else {
            FilterVerdict::DirectPassThrough {
                egress_tag: spatial_egress,
            }
        }
    }

    pub fn total_evaluated(&self) -> u64 {
        self.total_evaluated_queries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intelligent_traffic_filter_workflow() {
        let mut filter = IntelligentTrafficFilter::new("direct-egress");
        filter.dns_blocklist.add_exact_rule("bad-ads.net", BlockCategory::Advertising);
        filter.canonical_rules.parse_raw_rule("||blocked-portal.org");

        let src: SocketAddr = "127.0.0.1:51234".parse().unwrap();
        let dst: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let payload = [0x16, 0x03, 0x01, 0x00, 0x20]; // TLS ClientHello header

        // Test advertising block
        let v1 = filter.evaluate_traffic(src, dst, Some("bad-ads.net"), None, &payload);
        assert_eq!(v1, FilterVerdict::BlockedDns(BlockCategory::Advertising));

        // Test proxy routing requirement
        let v2 = filter.evaluate_traffic(src, dst, Some("blocked-portal.org"), None, &payload);
        assert_eq!(
            v2,
            FilterVerdict::ProxyRequired {
                rule_hit: "blocked-portal.org".to_string(),
                egress_tag: "tunnel-proxy".to_string()
            }
        );

        // Test clean pass through
        let v3 = filter.evaluate_traffic(src, dst, Some("example.com"), None, &payload);
        assert_eq!(
            v3,
            FilterVerdict::DirectPassThrough {
                egress_tag: "default-direct".to_string()
            }
        );
    }
}
