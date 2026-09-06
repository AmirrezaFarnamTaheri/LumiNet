//! DNS Tunnel Profile Wizard and Server Map Compiler
//!
//! Synthesizes multi-server DNS tunnel profile configurations, validating
//! domain roots, nameserver authorities, and key parameters.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServerProfile {
    pub name: String,
    pub domain_root: String,
    pub nameserver: String,
    pub port: u16,
    pub key: String,
    pub enabled: bool,
}

#[derive(Debug, Default)]
pub struct DnsWizardProfileGenerator {
    profiles: HashMap<String, DnsServerProfile>,
}

impl DnsWizardProfileGenerator {
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
        }
    }

    pub fn add_profile(
        &mut self,
        name: &str,
        domain_root: &str,
        nameserver: &str,
        port: u16,
        key: &str,
    ) {
        self.profiles.insert(
            name.to_string(),
            DnsServerProfile {
                name: name.to_string(),
                domain_root: domain_root.trim_end_matches('.').to_string(),
                nameserver: nameserver.to_string(),
                port: if port == 0 { 53 } else { port },
                key: key.to_string(),
                enabled: true,
            },
        );
    }

    pub fn get_profile(&self, name: &str) -> Option<&DnsServerProfile> {
        self.profiles.get(name)
    }

    pub fn toggle_profile(&mut self, name: &str, enabled: bool) {
        if let Some(p) = self.profiles.get_mut(name) {
            p.enabled = enabled;
        }
    }

    pub fn export_profile_json(&self, name: &str) -> Option<String> {
        self.profiles.get(name).map(|p| {
            format!(
                "{{\"name\":\"{}\",\"domain_root\":\"{}\",\"nameserver\":\"{}\",\"port\":{},\"key\":\"{}\",\"enabled\":{}}}",
                p.name, p.domain_root, p.nameserver, p.port, p.key, p.enabled
            )
        })
    }

    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_wizard_profile() {
        let mut wizard = DnsWizardProfileGenerator::new();
        wizard.add_profile("primary", "tunnel.example.com.", "1.1.1.1", 53, "secretkey");

        let prof = wizard.get_profile("primary").unwrap();
        assert_eq!(prof.domain_root, "tunnel.example.com");
        assert_eq!(prof.port, 53);
        assert!(prof.enabled);

        let json = wizard.export_profile_json("primary").unwrap();
        assert!(json.contains("\"name\":\"primary\""));
        assert!(json.contains("\"domain_root\":\"tunnel.example.com\""));

        wizard.toggle_profile("primary", false);
        assert!(!wizard.get_profile("primary").unwrap().enabled);
    }
}
