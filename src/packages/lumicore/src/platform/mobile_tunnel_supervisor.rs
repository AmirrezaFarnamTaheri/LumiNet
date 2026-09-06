//! # Universal Mobile Tunnel Supervisor
//!
//! Supervises mobile VPN TUN lifecycle, package-based split tunneling filtering,
//! MTU negotiation, and seamless reconnect states.

use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MobileTunnelState {
    Stopped,
    Starting,
    Running,
    Pausing,
    Reconnecting,
    Failed,
}

#[derive(Debug, Clone)]
pub struct MobileTunnelConfig {
    pub tun_name: String,
    pub mtu: u16,
    pub ipv4_address: String,
    pub ipv4_netmask: String,
    pub dns_servers: Vec<String>,
    pub included_packages: HashSet<String>,
    pub excluded_packages: HashSet<String>,
}

pub struct MobileTunnelSupervisor {
    config: MobileTunnelConfig,
    state: MobileTunnelState,
    active_tun_fd: Option<i32>,
    total_reconnects: u32,
}

impl MobileTunnelSupervisor {
    pub fn new(config: MobileTunnelConfig) -> Self {
        Self {
            config,
            state: MobileTunnelState::Stopped,
            active_tun_fd: None,
            total_reconnects: 0,
        }
    }

    pub fn start(&mut self, tun_fd: i32) -> Result<(), &'static str> {
        if self.state == MobileTunnelState::Running {
            return Err("Tunnel already running");
        }
        self.active_tun_fd = Some(tun_fd);
        self.state = MobileTunnelState::Running;
        Ok(())
    }

    pub fn stop(&mut self) {
        self.state = MobileTunnelState::Stopped;
        self.active_tun_fd = None;
    }

    pub fn trigger_reconnect(&mut self) {
        self.total_reconnects += 1;
        self.state = MobileTunnelState::Reconnecting;
    }

    pub fn is_package_routed(&self, package_name: &str) -> bool {
        // Excluded takes precedence
        if self.config.excluded_packages.contains(package_name) {
            return false;
        }
        // If inclusion list is not empty, must be in inclusion list
        if !self.config.included_packages.is_empty() {
            return self.config.included_packages.contains(package_name);
        }
        // By default, route all
        true
    }

    pub fn state(&self) -> MobileTunnelState {
        self.state
    }

    pub fn tun_fd(&self) -> Option<i32> {
        self.active_tun_fd
    }

    pub fn reconnect_count(&self) -> u32 {
        self.total_reconnects
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mobile_tunnel_lifecycle() {
        let mut inc = HashSet::new();
        inc.insert("com.android.chrome".to_string());
        let mut exc = HashSet::new();
        exc.insert("com.bank.app".to_string());

        let cfg = MobileTunnelConfig {
            tun_name: "tun0".to_string(),
            mtu: 1500,
            ipv4_address: "172.19.0.1".to_string(),
            ipv4_netmask: "255.255.255.0".to_string(),
            dns_servers: vec!["1.1.1.1".to_string()],
            included_packages: inc,
            excluded_packages: exc,
        };

        let mut sup = MobileTunnelSupervisor::new(cfg);
        assert_eq!(sup.state(), MobileTunnelState::Stopped);

        sup.start(10).unwrap();
        assert_eq!(sup.state(), MobileTunnelState::Running);
        assert_eq!(sup.tun_fd(), Some(10));

        assert!(sup.is_package_routed("com.android.chrome"));
        assert!(!sup.is_package_routed("com.bank.app"));
        assert!(!sup.is_package_routed("com.other.app")); // because included_packages is non-empty

        sup.trigger_reconnect();
        assert_eq!(sup.state(), MobileTunnelState::Reconnecting);
        assert_eq!(sup.reconnect_count(), 1);
    }
}
