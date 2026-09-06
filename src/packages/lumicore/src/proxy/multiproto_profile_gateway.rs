//! # Multiproto Profile Gateway (Synthesis C2)
//!
//! Master enterprise gateway orchestrator integrating multi-protocol profile management,
//! OpenVPN configuration transpilation, node diversity sampling, and reverse relay dispatch.

use crate::diagnostics::node_diversity_sampler::{DiversityMetrics, DiversityNodeDescriptor, NodeDiversitySampler};
use crate::platform::protocol_profile_orchestrator::{ProtocolProfile, ProtocolProfileOrchestrator, SupportedProtocol};
use crate::proxy::hybrid_shadow_v2_transport::{HybridEndpointConfig, HybridProtocolType, HybridShadowV2Transport};
use crate::proxy::ovpn_config_transpiler::OvpnConfigTranspiler;
use crate::security::enterprise_vpn_controller::{EnterpriseVpnController, TenantOrganization, UserRole};
use crate::transport::reverse_tunnel_relay::ReverseTunnelRelay;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayOverview {
    pub total_profiles: usize,
    pub total_active_users: usize,
    pub total_reverse_channels: usize,
    pub diversity: DiversityMetrics,
}

pub struct MultiprotoProfileGateway {
    profile_orchestrator: ProtocolProfileOrchestrator,
    hybrid_transport: HybridShadowV2Transport,
    enterprise_controller: EnterpriseVpnController,
    diversity_sampler: NodeDiversitySampler,
    reverse_relay: ReverseTunnelRelay,
}

impl MultiprotoProfileGateway {
    pub fn new(org: TenantOrganization, relay_timeout_secs: u64) -> Self {
        let mut enterprise = EnterpriseVpnController::new();
        enterprise.register_organization(org);

        Self {
            profile_orchestrator: ProtocolProfileOrchestrator::new(),
            hybrid_transport: HybridShadowV2Transport::new(),
            enterprise_controller: enterprise,
            diversity_sampler: NodeDiversitySampler::new(),
            reverse_relay: ReverseTunnelRelay::new(relay_timeout_secs),
        }
    }

    pub fn import_ovpn_profile(&mut self, profile_id: &str, raw_ovpn: &str) -> Result<(), String> {
        let transpiled = OvpnConfigTranspiler::parse(raw_ovpn)?;
        let profile = ProtocolProfile {
            profile_id: profile_id.to_string(),
            protocol: SupportedProtocol::Openvpn,
            server_endpoint: format!("{}:{}", transpiled.remote_host, transpiled.remote_port),
            config_payload: serde_json::to_string(&transpiled).unwrap_or_default(),
            is_favorite: false,
            last_used: 0,
        };
        self.profile_orchestrator.save_profile(profile);
        Ok(())
    }

    pub fn register_enterprise_user(
        &mut self,
        user_id: &str,
        org_id: &str,
        role: UserRole,
        token: &str,
        vip: &str,
        routes: Vec<String>,
    ) -> Result<(), String> {
        self.enterprise_controller
            .register_user(user_id, org_id, role, token, vip, routes)
    }

    pub fn register_hybrid_endpoint(&mut self, id: &str, host: &str, port: u16, proto: HybridProtocolType, token: &str, weight: u32) {
        self.hybrid_transport.register_endpoint(HybridEndpointConfig {
            endpoint_id: id.to_string(),
            host: host.to_string(),
            port,
            protocol: proto,
            credentials_token: token.to_string(),
            weight,
        });
    }

    pub fn track_node_diversity(&mut self, node: DiversityNodeDescriptor) {
        self.diversity_sampler.add_node(node);
    }

    pub fn open_reverse_edge_channel(&mut self, edge_node_id: &str, timestamp: u64) -> u32 {
        self.reverse_relay.open_channel(edge_node_id, timestamp)
    }

    pub fn get_overview(&self) -> GatewayOverview {
        GatewayOverview {
            total_profiles: self.profile_orchestrator.total_profiles(),
            total_active_users: self.enterprise_controller.total_active_users(),
            total_reverse_channels: self.reverse_relay.total_active_channels(),
            diversity: self.diversity_sampler.compute_diversity_metrics(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multiproto_profile_gateway_integration() {
        let org = TenantOrganization {
            org_id: "org-global".to_string(),
            name: "Global Network".to_string(),
            virtual_subnet: "10.100.0.0/16".to_string(),
            max_users: 50,
            enable_split_tunnel: true,
        };

        let mut gw = MultiprotoProfileGateway::new(org, 60);

        // Import OVPN
        let ovpn = "remote ovpn.node.net 1194 udp\ncipher AES-256-GCM\nauth-user-pass\n";
        gw.import_ovpn_profile("ovpn-node-1", ovpn).unwrap();

        // Register user
        gw.register_enterprise_user(
            "operator",
            "org-global",
            UserRole::Admin,
            "secret-token-op",
            "10.100.1.5",
            vec![],
        )
        .unwrap();

        // Register hybrid endpoint
        gw.register_hybrid_endpoint("ss-1", "1.2.3.4", 8388, HybridProtocolType::Shadowsocks, "key", 100);

        // Track node diversity
        gw.track_node_diversity(DiversityNodeDescriptor {
            node_id: "node-us".to_string(),
            asn: 13335,
            country_code: "US".to_string(),
            ip_prefix_24: "1.2.3.0".to_string(),
            latency_ms: 30,
        });

        // Open reverse channel
        gw.open_reverse_edge_channel("edge-router-1", 1000);

        let overview = gw.get_overview();
        assert_eq!(overview.total_profiles, 1);
        assert_eq!(overview.total_active_users, 1);
        assert_eq!(overview.total_reverse_channels, 1);
        assert_eq!(overview.diversity.total_nodes, 1);
    }
}
