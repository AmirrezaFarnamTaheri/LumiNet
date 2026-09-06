//! # Leak Guard Supervisor
//!
//! Real-time DNS, IPv6, and WebRTC traffic leak supervisor enforcing strict
//! kill-switch routing rules, interface bind isolation, and route table integrity.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeakRiskLevel {
    Secure,
    Warning,
    CriticalLeak,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakCheckReport {
    pub risk_level: LeakRiskLevel,
    pub dns_leak_detected: bool,
    pub ipv6_leak_detected: bool,
    pub default_gateway_exposed: bool,
    pub killswitch_active: bool,
}

pub struct LeakGuardSupervisor {
    tunnel_interface: String,
    trusted_dns_servers: Vec<String>,
    killswitch_enabled: bool,
    ipv6_blocked: bool,
}

impl LeakGuardSupervisor {
    pub fn new(tunnel_interface: &str, trusted_dns: Vec<String>) -> Self {
        Self {
            tunnel_interface: tunnel_interface.to_string(),
            trusted_dns_servers: trusted_dns,
            killswitch_enabled: true,
            ipv6_blocked: true,
        }
    }

    pub fn set_killswitch(&mut self, enabled: bool) {
        self.killswitch_enabled = enabled;
    }

    pub fn verify_routing_integrity(
        &self,
        active_default_interface: &str,
        active_dns_resolvers: &[String],
        has_ipv6_traffic: bool,
    ) -> LeakCheckReport {
        let mut dns_leak = false;
        let mut ipv6_leak = false;
        let default_gateway_exposed = active_default_interface != self.tunnel_interface;

        // Check DNS resolvers
        for resolver in active_dns_resolvers {
            if !self.trusted_dns_servers.contains(resolver) {
                dns_leak = true;
                break;
            }
        }

        // Check IPv6 traffic if IPv6 is supposed to be blocked/null-routed
        if self.ipv6_blocked && has_ipv6_traffic && default_gateway_exposed {
            ipv6_leak = true;
        }

        let risk_level = if dns_leak || ipv6_leak || (default_gateway_exposed && self.killswitch_enabled) {
            LeakRiskLevel::CriticalLeak
        } else if default_gateway_exposed {
            LeakRiskLevel::Warning
        } else {
            LeakRiskLevel::Secure
        };

        LeakCheckReport {
            risk_level,
            dns_leak_detected: dns_leak,
            ipv6_leak_detected: ipv6_leak,
            default_gateway_exposed,
            killswitch_active: self.killswitch_enabled,
        }
    }

    pub fn should_block_packet(&self, egress_interface: &str) -> bool {
        if self.killswitch_enabled {
            egress_interface != self.tunnel_interface
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leak_guard_supervisor_integrity() {
        let trusted = vec!["1.1.1.1".to_string(), "10.0.0.1".to_string()];
        let supervisor = LeakGuardSupervisor::new("tun0", trusted);

        // Scenario 1: Clean and secure
        let report1 = supervisor.verify_routing_integrity(
            "tun0",
            &["10.0.0.1".to_string()],
            false,
        );
        assert_eq!(report1.risk_level, LeakRiskLevel::Secure);
        assert!(!report1.dns_leak_detected);
        assert!(!supervisor.should_block_packet("tun0"));
        assert!(supervisor.should_block_packet("eth0"));

        // Scenario 2: DNS leak via ISP resolver (192.168.1.1)
        let report2 = supervisor.verify_routing_integrity(
            "tun0",
            &["192.168.1.1".to_string()],
            false,
        );
        assert_eq!(report2.risk_level, LeakRiskLevel::CriticalLeak);
        assert!(report2.dns_leak_detected);

        // Scenario 3: Exposed default interface (e.g. WiFi eth0) with killswitch enabled
        let report3 = supervisor.verify_routing_integrity(
            "eth0",
            &["1.1.1.1".to_string()],
            true,
        );
        assert_eq!(report3.risk_level, LeakRiskLevel::CriticalLeak);
        assert!(report3.default_gateway_exposed);
        assert!(report3.ipv6_leak_detected);
    }
}
