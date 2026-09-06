//! Adaptive WireGuard MTU and Path MSS Discovery Engine
//!
//! Iteratively converges on optimal tunnel MTU via binary probing and
//! calculates optimal keepalive cadence to prevent NAT mapping drops.

#[derive(Debug, Clone)]
pub struct AdaptiveMtuDiscovery {
    min_mtu: u16,
    max_mtu: u16,
    current_probe: u16,
    converged_mtu: Option<u16>,
    probe_history: Vec<(u16, bool)>,
}

impl Default for AdaptiveMtuDiscovery {
    fn default() -> Self {
        Self::new(1280, 1500)
    }
}

impl AdaptiveMtuDiscovery {
    pub fn new(min_mtu: u16, max_mtu: u16) -> Self {
        let initial_probe = (min_mtu + max_mtu) / 2;
        Self {
            min_mtu,
            max_mtu,
            current_probe: initial_probe,
            converged_mtu: None,
            probe_history: Vec::new(),
        }
    }

    /// Returns the next MTU payload size to probe
    pub fn next_probe_size(&self) -> u16 {
        self.current_probe
    }

    /// Feed probe ack result: true if packet was acknowledged without fragmentation
    pub fn record_result(&mut self, size: u16, success: bool) {
        self.probe_history.push((size, success));

        if success {
            self.min_mtu = size;
        } else {
            self.max_mtu = size.saturating_sub(1);
        }

        if self.min_mtu >= self.max_mtu {
            self.converged_mtu = Some(self.min_mtu);
        } else {
            self.current_probe = (self.min_mtu + self.max_mtu + 1) / 2;
        }
    }

    /// Returns the converged optimal MTU or the current best lower bound
    pub fn optimal_mtu(&self) -> u16 {
        self.converged_mtu.unwrap_or(self.min_mtu)
    }

    /// Determines WireGuard payload MTU accounting for IPv4 (60B) or IPv6 (80B) overhead
    pub fn wireguard_payload_mtu(&self, is_ipv6: bool) -> u16 {
        let overhead = if is_ipv6 { 80 } else { 60 };
        self.optimal_mtu().saturating_sub(overhead)
    }

    /// Optimal persistent keepalive seconds based on path MTU volatility
    pub fn optimal_keepalive_secs(&self) -> u32 {
        if self.optimal_mtu() < 1360 {
            15 // More aggressive keepalive on constrained mobile/carrier NATs
        } else {
            25
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mtu_convergence() {
        let mut engine = AdaptiveMtuDiscovery::new(1280, 1500);
        // Simulate path where 1420 succeeds, 1421+ fails
        for _ in 0..10 {
            let probe = engine.next_probe_size();
            let ok = probe <= 1420;
            engine.record_result(probe, ok);
            if engine.converged_mtu.is_some() {
                break;
            }
        }
        assert_eq!(engine.optimal_mtu(), 1420);
        assert_eq!(engine.wireguard_payload_mtu(false), 1360);
        assert_eq!(engine.optimal_keepalive_secs(), 25);
    }
}
