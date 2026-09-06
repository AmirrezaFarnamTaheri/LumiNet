//! # Desktop Client Manager
//!
//! Cross-platform desktop proxy controller, system proxy mode supervisor,
//! and IPC event router for desktop client frontends.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SystemProxyMode {
    Direct,
    Pac,
    Global,
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopStatus {
    pub mode: SystemProxyMode,
    pub active_profile: String,
    pub http_port: u16,
    pub socks5_port: u16,
    pub is_connected: bool,
    pub pac_url: Option<String>,
}

pub struct DesktopClientManager {
    mode: SystemProxyMode,
    active_profile: String,
    http_port: u16,
    socks5_port: u16,
    is_connected: bool,
    pac_url: Option<String>,
}

impl DesktopClientManager {
    pub fn new(http_port: u16, socks5_port: u16) -> Self {
        Self {
            mode: SystemProxyMode::Direct,
            active_profile: "default".to_string(),
            http_port,
            socks5_port,
            is_connected: false,
            pac_url: None,
        }
    }

    pub fn set_proxy_mode(&mut self, mode: SystemProxyMode, pac_url: Option<String>) -> Result<(), String> {
        if mode == SystemProxyMode::Pac && pac_url.is_none() && self.pac_url.is_none() {
            return Err("PAC mode requires a valid PAC URL".to_string());
        }

        self.mode = mode;
        if pac_url.is_some() {
            self.pac_url = pac_url;
        }
        Ok(())
    }

    pub fn switch_profile(&mut self, profile_id: &str) {
        self.active_profile = profile_id.to_string();
    }

    pub fn set_connected(&mut self, connected: bool) {
        self.is_connected = connected;
    }

    pub fn get_status(&self) -> DesktopStatus {
        DesktopStatus {
            mode: self.mode,
            active_profile: self.active_profile.clone(),
            http_port: self.http_port,
            socks5_port: self.socks5_port,
            is_connected: self.is_connected,
            pac_url: self.pac_url.clone(),
        }
    }

    pub fn handle_ipc_command(&mut self, command: &str, payload: serde_json::Value) -> Result<serde_json::Value, String> {
        match command {
            "get_status" => {
                let status = self.get_status();
                serde_json::to_value(status).map_err(|e| e.to_string())
            }
            "set_mode" => {
                let mode_str = payload.get("mode").and_then(|v| v.as_str()).ok_or("Missing mode")?;
                let pac_url = payload.get("pac_url").and_then(|v| v.as_str()).map(|s| s.to_string());
                let mode = match mode_str {
                    "direct" => SystemProxyMode::Direct,
                    "pac" => SystemProxyMode::Pac,
                    "global" => SystemProxyMode::Global,
                    "manual" => SystemProxyMode::Manual,
                    _ => return Err("Invalid proxy mode".to_string()),
                };
                self.set_proxy_mode(mode, pac_url)?;
                Ok(serde_json::json!({ "success": true }))
            }
            "switch_profile" => {
                let profile = payload.get("profile").and_then(|v| v.as_str()).ok_or("Missing profile")?;
                self.switch_profile(profile);
                Ok(serde_json::json!({ "success": true, "profile": profile }))
            }
            _ => Err(format!("Unknown command: {}", command)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_desktop_client_manager() {
        let mut mgr = DesktopClientManager::new(7890, 7891);
        let status = mgr.get_status();
        assert_eq!(status.mode, SystemProxyMode::Direct);
        assert!(!status.is_connected);

        let res = mgr.handle_ipc_command("set_mode", serde_json::json!({ "mode": "global" }));
        assert!(res.is_ok());
        assert_eq!(mgr.get_status().mode, SystemProxyMode::Global);

        let res2 = mgr.handle_ipc_command("switch_profile", serde_json::json!({ "profile": "us_east_node" }));
        assert!(res2.is_ok());
        assert_eq!(mgr.get_status().active_profile, "us_east_node");
    }
}
