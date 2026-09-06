//! Edge Subscription Route Pipeline and Clean IP Permutator
//!
//! Generates multi-protocol subscription feeds by combining edge worker endpoints
//! with dynamic clean IP candidates and failover weights.

use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct SubscriptionNode {
    pub name: String,
    pub clean_ip: String,
    pub port: u16,
    pub uuid: String,
    pub sni: String,
    pub host: String,
}

#[derive(Debug, Default)]
pub struct EdgeSubscriptionPipeline {
    clean_ips: Vec<String>,
    workers: Vec<(String, String)>, // (domain, sni)
}

impl EdgeSubscriptionPipeline {
    pub fn new() -> Self {
        Self {
            clean_ips: Vec::new(),
            workers: Vec::new(),
        }
    }

    pub fn add_clean_ip(&mut self, ip: &str) {
        if !self.clean_ips.iter().any(|existing| existing == ip) {
            self.clean_ips.push(ip.to_string());
        }
    }

    pub fn add_worker(&mut self, domain: &str, sni: &str) {
        self.workers.push((domain.to_string(), sni.to_string()));
    }

    pub fn generate_nodes(&self, uuid: &str) -> Vec<SubscriptionNode> {
        let mut nodes = Vec::new();
        for (domain, sni) in &self.workers {
            for (idx, ip) in self.clean_ips.iter().enumerate() {
                nodes.push(SubscriptionNode {
                    name: format!("{}-node-{}", domain, idx + 1),
                    clean_ip: ip.clone(),
                    port: 443,
                    uuid: uuid.to_string(),
                    sni: sni.clone(),
                    host: domain.clone(),
                });
            }
        }
        nodes
    }

    pub fn export_base64_subscription(&self, uuid: &str) -> String {
        let nodes = self.generate_nodes(uuid);
        let mut lines = Vec::new();
        for n in nodes {
            lines.push(format!(
                "vless://{}@{}:{}?encryption=none&security=tls&sni={}&type=ws&host={}&path=%2F#{}",
                n.uuid, n.clean_ip, n.port, n.sni, n.host, n.name
            ));
        }
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subscription_pipeline() {
        let mut pipe = EdgeSubscriptionPipeline::new();
        pipe.add_clean_ip("104.16.10.1");
        pipe.add_clean_ip("104.16.10.2");
        pipe.add_worker("worker.pages.dev", "worker.pages.dev");

        let nodes = pipe.generate_nodes("user-uuid");
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].clean_ip, "104.16.10.1");
        assert_eq!(nodes[1].clean_ip, "104.16.10.2");

        let feed = pipe.export_base64_subscription("user-uuid");
        assert!(feed.contains("104.16.10.1:443"));
        assert!(feed.contains("104.16.10.2:443"));
    }
}
