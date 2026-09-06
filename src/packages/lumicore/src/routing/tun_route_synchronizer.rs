//! TUN Route Table Synchronizer and MTU Clamp Engine
//!
//! Computes bypass CIDR tables (RFC 1918, link-local, multicast) and clamps
//! TCP MSS appropriately to eliminate path packet fragmentation.

#[derive(Debug, Clone)]
pub struct TunRouteSynchronizer {
    bypass_prefixes: Vec<String>,
    tun_mtu: u16,
}

impl Default for TunRouteSynchronizer {
    fn default() -> Self {
        Self {
            bypass_prefixes: vec![
                "10.".to_string(),
                "127.".to_string(),
                "169.254.".to_string(),
                "172.16.".to_string(),
                "192.168.".to_string(),
                "224.".to_string(),
                "fe80:".to_string(),
                "::1".to_string(),
            ],
            tun_mtu: 1500,
        }
    }
}

impl TunRouteSynchronizer {
    pub fn new(tun_mtu: u16) -> Self {
        let mut s = Self::default();
        s.tun_mtu = tun_mtu;
        s
    }

    pub fn add_bypass_prefix(&mut self, prefix: &str) {
        if !self.bypass_prefixes.iter().any(|p| p == prefix) {
            self.bypass_prefixes.push(prefix.to_string());
        }
    }

    /// Evaluates if an IP should bypass the TUN interface (routed directly)
    pub fn should_bypass(&self, ip: &str) -> bool {
        let trimmed = ip.trim();
        for prefix in &self.bypass_prefixes {
            if trimmed.starts_with(prefix) {
                return true;
            }
        }
        false
    }

    /// Computes clamped TCP Maximum Segment Size (MSS)
    /// IPv4 overhead: 20 bytes IP + 20 bytes TCP = 40 bytes.
    /// IPv6 overhead: 40 bytes IP + 20 bytes TCP = 60 bytes.
    pub fn calculate_clamped_mss(&self, is_ipv6: bool) -> u16 {
        let overhead = if is_ipv6 { 60 } else { 40 };
        self.tun_mtu.saturating_sub(overhead)
    }

    pub fn tun_mtu(&self) -> u16 {
        self.tun_mtu
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bypass_and_mss() {
        let sync = TunRouteSynchronizer::new(1400);
        assert!(sync.should_bypass("192.168.1.1"));
        assert!(sync.should_bypass("10.0.0.5"));
        assert!(!sync.should_bypass("1.1.1.1"));
        assert!(!sync.should_bypass("8.8.8.8"));

        assert_eq!(sync.calculate_clamped_mss(false), 1360);
        assert_eq!(sync.calculate_clamped_mss(true), 1340);
    }
}
