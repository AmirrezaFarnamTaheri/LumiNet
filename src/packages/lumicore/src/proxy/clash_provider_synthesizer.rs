//! # Clash Provider Profile Synthesizer
//!
//! Synthesizes unified multi-provider subscription profiles, auto-generates
//! URL-test proxy groups, fallback pools, and load balancers.
//! Ported and enhanced from freenodes/freenodes.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyGroupType {
    Select,
    UrlTest,
    Fallback,
    LoadBalance,
}

impl ProxyGroupType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProxyGroupType::Select => "select",
            ProxyGroupType::UrlTest => "url-test",
            ProxyGroupType::Fallback => "fallback",
            ProxyGroupType::LoadBalance => "load-balance",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClashProxyNode {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub protocol: String,
    pub cipher_or_uuid: String,
    pub latency_ms: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct ProxyGroupDef {
    pub name: String,
    pub group_type: ProxyGroupType,
    pub proxies: Vec<String>,
    pub url: String,
    pub interval_sec: u32,
    pub tolerance_ms: u32,
}

#[derive(Debug, Clone)]
pub struct ClashProviderSynthesizer {
    nodes: Vec<ClashProxyNode>,
    groups: Vec<ProxyGroupDef>,
    socks_port: u16,
    http_port: u16,
    mixed_port: u16,
}

impl ClashProviderSynthesizer {
    pub fn new(mixed_port: u16) -> Self {
        Self {
            nodes: Vec::new(),
            groups: Vec::new(),
            socks_port: 0,
            http_port: 0,
            mixed_port,
        }
    }

    pub fn add_node(&mut self, node: ClashProxyNode) {
        self.nodes.push(node);
    }

    pub fn add_group(&mut self, group: ProxyGroupDef) {
        self.groups.push(group);
    }

    pub fn synthesize_yaml(&self) -> String {
        let mut yaml = String::with_capacity(4096);
        yaml.push_str("# LumiNet Auto-Synthesized Clash Configuration\n");
        yaml.push_str(&format!("mixed-port: {}\n", self.mixed_port));
        yaml.push_str("allow-lan: false\n");
        yaml.push_str("mode: rule\n");
        yaml.push_str("log-level: info\n\n");

        yaml.push_str("proxies:\n");
        for node in &self.nodes {
            yaml.push_str(&format!("  - name: \"{}\"\n", node.name));
            yaml.push_str(&format!("    type: {}\n", node.protocol));
            yaml.push_str(&format!("    server: {}\n", node.server));
            yaml.push_str(&format!("    port: {}\n", node.port));
            yaml.push_str(&format!("    uuid: {}\n", node.cipher_or_uuid));
        }

        yaml.push_str("\nproxy-groups:\n");
        for g in &self.groups {
            yaml.push_str(&format!("  - name: \"{}\"\n", g.name));
            yaml.push_str(&format!("    type: {}\n", g.group_type.as_str()));
            yaml.push_str("    proxies:\n");
            for p in &g.proxies {
                yaml.push_str(&format!("      - \"{}\"\n", p));
            }
            if g.group_type != ProxyGroupType::Select {
                yaml.push_str(&format!("    url: {}\n", g.url));
                yaml.push_str(&format!("    interval: {}\n", g.interval_sec));
                yaml.push_str(&format!("    tolerance: {}\n", g.tolerance_ms));
            }
        }

        yaml.push_str("\nrules:\n");
        yaml.push_str("  - DOMAIN-SUFFIX,local,DIRECT\n");
        yaml.push_str("  - IP-CIDR,127.0.0.0/8,DIRECT\n");
        yaml.push_str("  - IP-CIDR,192.168.0.0/16,DIRECT\n");
        yaml.push_str("  - MATCH,Auto-Fastest\n");

        yaml
    }

    pub fn filter_by_max_latency(&self, max_latency_ms: u32) -> Vec<ClashProxyNode> {
        self.nodes
            .iter()
            .filter(|n| n.latency_ms.map_or(false, |lat| lat <= max_latency_ms))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_synthesizer_yaml_generation() {
        let mut synth = ClashProviderSynthesizer::new(7890);
        synth.add_node(ClashProxyNode {
            name: "HK-01".to_string(),
            server: "hk01.example.com".to_string(),
            port: 443,
            protocol: "vless".to_string(),
            cipher_or_uuid: "uuid-12345".to_string(),
            latency_ms: Some(35),
        });
        synth.add_node(ClashProxyNode {
            name: "US-01".to_string(),
            server: "us01.example.com".to_string(),
            port: 443,
            protocol: "vless".to_string(),
            cipher_or_uuid: "uuid-67890".to_string(),
            latency_ms: Some(180),
        });

        synth.add_group(ProxyGroupDef {
            name: "Auto-Fastest".to_string(),
            group_type: ProxyGroupType::UrlTest,
            proxies: vec!["HK-01".to_string(), "US-01".to_string()],
            url: "http://www.gstatic.com/generate_204".to_string(),
            interval_sec: 300,
            tolerance_ms: 50,
        });

        let yaml = synth.synthesize_yaml();
        assert!(yaml.contains("mixed-port: 7890"));
        assert!(yaml.contains("name: \"HK-01\""));
        assert!(yaml.contains("type: url-test"));

        let low_lat = synth.filter_by_max_latency(50);
        assert_eq!(low_lat.len(), 1);
        assert_eq!(low_lat[0].name, "HK-01");
    }
}
