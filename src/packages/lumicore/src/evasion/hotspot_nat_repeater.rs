#[derive(Debug, Clone)]
pub struct HotspotRepeaterConfig {
    pub downstream_interface: String, // e.g. "wlan1" or "ap0"
    pub upstream_vpn_interface: String, // e.g. "tun0"
    pub downstream_subnet: String, // e.g. "192.168.43.0/24"
    pub clamp_mss_bytes: u16, // e.g. 1360
}

impl Default for HotspotRepeaterConfig {
    fn default() -> Self {
        Self {
            downstream_interface: "wlan1".to_string(),
            upstream_vpn_interface: "tun0".to_string(),
            downstream_subnet: "192.168.43.0/24".to_string(),
            clamp_mss_bytes: 1360,
        }
    }
}

pub struct HotspotNatRepeater {
    config: HotspotRepeaterConfig,
}

impl HotspotNatRepeater {
    pub fn new(cfg: HotspotRepeaterConfig) -> Self {
        Self { config: cfg }
    }

    pub fn generate_iptables_commands(&self) -> Vec<String> {
        vec![
            // Enable IP forwarding
            "echo 1 > /proc/sys/net/ipv4/ip_forward".to_string(),
            // Forward between AP interface and VPN interface
            format!("iptables -A FORWARD -i {} -o {} -j ACCEPT", self.config.downstream_interface, self.config.upstream_vpn_interface),
            format!("iptables -A FORWARD -i {} -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT", self.config.upstream_vpn_interface, self.config.downstream_interface),
            // Masquerade outbound traffic from hotspot subnet
            format!("iptables -t nat -A POSTROUTING -s {} -o {} -j MASQUERADE", self.config.downstream_subnet, self.config.upstream_vpn_interface),
            // MSS clamping to prevent fragmentation drops over VPN
            format!("iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hotspot_nat_rule_synthesis() {
        let repeater = HotspotNatRepeater::new(HotspotRepeaterConfig::default());
        let cmds = repeater.generate_iptables_commands();

        assert!(cmds.iter().any(|c| c.contains("-o tun0 -j MASQUERADE")));
        assert!(cmds.iter().any(|c| c.contains("TCPMSS --clamp-mss-to-pmtu")));
    }
}
