//! # Dynamic Firewall Killswitch & Provider Endpoint Filter
//!
//! Generates strict host firewall rules preventing traffic leaks outside the
//! VPN adapter and filters upstream VPN endpoints by geographic criteria.

use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderEndpoint {
    pub ip: IpAddr,
    pub port: u16,
    pub country_code: String,
    pub city: String,
    pub ping_ms: u32,
    pub supports_wireguard: bool,
}

#[derive(Debug, Clone)]
pub struct KillswitchRules {
    pub allow_loopback: bool,
    pub allow_lan: bool,
    pub vpn_adapter_name: String,
    pub vpn_remote_ip: IpAddr,
    pub vpn_remote_port: u16,
}

impl KillswitchRules {
    pub fn new(vpn_adapter_name: String, vpn_remote_ip: IpAddr, vpn_remote_port: u16, allow_lan: bool) -> Self {
        Self {
            allow_loopback: true,
            allow_lan,
            vpn_adapter_name,
            vpn_remote_ip,
            vpn_remote_port,
        }
    }

    /// Generates Linux iptables script for complete leak prevention
    pub fn generate_iptables_script(&self) -> String {
        let mut script = String::new();
        script.push_str("#!/bin/sh\n# LumiNet Gluetun-style Killswitch\n");
        script.push_str("iptables -F\niptables -X\niptables -P INPUT DROP\niptables -P FORWARD DROP\niptables -P OUTPUT DROP\n");
        script.push_str("iptables -A INPUT -i lo -j ACCEPT\niptables -A OUTPUT -o lo -j ACCEPT\n");
        if self.allow_lan {
            script.push_str("iptables -A OUTPUT -d 192.168.0.0/16 -j ACCEPT\n");
            script.push_str("iptables -A OUTPUT -d 10.0.0.0/8 -j ACCEPT\n");
            script.push_str("iptables -A OUTPUT -d 172.16.0.0/12 -j ACCEPT\n");
        }
        script.push_str(&format!(
            "iptables -A OUTPUT -d {} -p udp --dport {} -j ACCEPT\n",
            self.vpn_remote_ip, self.vpn_remote_port
        ));
        script.push_str(&format!(
            "iptables -A OUTPUT -o {} -j ACCEPT\n",
            self.vpn_adapter_name
        ));
        script
    }

    /// Generates Windows netsh / WFP rule summary
    pub fn generate_windows_wfp_commands(&self) -> Vec<String> {
        vec![
            format!("netsh advfirewall set allprofiles state on"),
            format!("netsh advfirewall firewall set rule group=\"all\" new enable=no"),
            format!("netsh advfirewall firewall add rule name=\"LumiNet_VPN\" dir=out action=allow remoteip={} protocol=UDP remoteport={}", self.vpn_remote_ip, self.vpn_remote_port),
        ]
    }
}

pub fn filter_endpoints<'a>(
    endpoints: &'a [ProviderEndpoint],
    country: Option<&str>,
    max_ping_ms: Option<u32>,
) -> Vec<&'a ProviderEndpoint> {
    endpoints
        .iter()
        .filter(|e| {
            if let Some(c) = country {
                if !e.country_code.eq_ignore_ascii_case(c) {
                    return false;
                }
            }
            if let Some(max_p) = max_ping_ms {
                if e.ping_ms > max_p {
                    return false;
                }
            }
            true
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_killswitch_rule_generation() {
        let rules = KillswitchRules::new("lumitun0".to_string(), IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 51820, true);
        let iptables = rules.generate_iptables_script();
        assert!(iptables.contains("iptables -P OUTPUT DROP"));
        assert!(iptables.contains("198.51.100.1"));
        assert!(iptables.contains("lumitun0"));

        let wfp = rules.generate_windows_wfp_commands();
        assert!(wfp.len() >= 3);
    }
}
