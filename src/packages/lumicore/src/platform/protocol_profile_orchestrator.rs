//! # Protocol Profile Orchestrator
//!
//! Universal VPN protocol client profile manager supporting dynamic switching
//! between WireGuard, OpenVPN, Shadowsocks, Cloak, and AmneziaWG engines with credential caching.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SupportedProtocol {
    Wireguard,
    Openvpn,
    Shadowsocks,
    Cloak,
    Amneziawg,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolProfile {
    pub profile_id: String,
    pub protocol: SupportedProtocol,
    pub server_endpoint: String,
    pub config_payload: String,
    pub is_favorite: bool,
    pub last_used: u64,
}

pub struct ProtocolProfileOrchestrator {
    profiles: HashMap<String, ProtocolProfile>,
    active_profile_id: Option<String>,
}

impl ProtocolProfileOrchestrator {
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
            active_profile_id: None,
        }
    }

    pub fn save_profile(&mut self, profile: ProtocolProfile) {
        let id = profile.profile_id.clone();
        if self.active_profile_id.is_none() {
            self.active_profile_id = Some(id.clone());
        }
        self.profiles.insert(id, profile);
    }

    pub fn activate_profile(&mut self, profile_id: &str, timestamp: u64) -> Result<&ProtocolProfile, String> {
        if let Some(profile) = self.profiles.get_mut(profile_id) {
            profile.last_used = timestamp;
            self.active_profile_id = Some(profile_id.to_string());
            Ok(profile)
        } else {
            Err("Profile not found".to_string())
        }
    }

    pub fn get_active_profile(&self) -> Option<&ProtocolProfile> {
        self.active_profile_id
            .as_ref()
            .and_then(|id| self.profiles.get(id))
    }

    pub fn filter_by_protocol(&self, proto: SupportedProtocol) -> Vec<&ProtocolProfile> {
        self.profiles
            .values()
            .filter(|p| p.protocol == proto)
            .collect()
    }

    pub fn delete_profile(&mut self, profile_id: &str) -> bool {
        if self.active_profile_id.as_deref() == Some(profile_id) {
            self.active_profile_id = None;
        }
        self.profiles.remove(profile_id).is_some()
    }

    pub fn total_profiles(&self) -> usize {
        self.profiles.len()
    }
}

impl Default for ProtocolProfileOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_profile_orchestrator() {
        let mut orch = ProtocolProfileOrchestrator::new();

        let wg = ProtocolProfile {
            profile_id: "wg-profile-1".to_string(),
            protocol: SupportedProtocol::Wireguard,
            server_endpoint: "wg.acme.net:51820".to_string(),
            config_payload: "[Interface]\nPrivateKey = ...".to_string(),
            is_favorite: true,
            last_used: 0,
        };

        let awg = ProtocolProfile {
            profile_id: "awg-profile-1".to_string(),
            protocol: SupportedProtocol::Amneziawg,
            server_endpoint: "awg.acme.net:51821".to_string(),
            config_payload: "Jc = 4\nJmin = 50".to_string(),
            is_favorite: false,
            last_used: 0,
        };

        orch.save_profile(wg);
        orch.save_profile(awg);

        assert_eq!(orch.total_profiles(), 2);
        assert_eq!(orch.filter_by_protocol(SupportedProtocol::Amneziawg).len(), 1);

        orch.activate_profile("awg-profile-1", 1000).unwrap();
        assert_eq!(orch.get_active_profile().unwrap().profile_id, "awg-profile-1");
        assert_eq!(orch.get_active_profile().unwrap().last_used, 1000);
    }
}
