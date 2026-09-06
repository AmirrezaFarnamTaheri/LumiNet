//! # Dual Backend Simultaneous Controller
//!
//! Orchestrates simultaneous dual-backend proxy engines (e.g. KCP/raw socket
//! and violated TCP/QUIC injection) with real-time RTT racing, loss tracking,
//! and seamless failover. Ported and enhanced from SamNet-dev/paqctl.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendEngineKind {
    KcpRawSocket,
    ViolatedTcpQuic,
    FallbackStandard,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EngineHealthMetric {
    pub rtt_ms: u32,
    pub packet_loss_rate: f32,
    pub consecutive_failures: u32,
    pub is_alive: bool,
    pub total_transmitted_bytes: u64,
}

impl Default for EngineHealthMetric {
    fn default() -> Self {
        Self {
            rtt_ms: 100,
            packet_loss_rate: 0.0,
            consecutive_failures: 0,
            is_alive: true,
            total_transmitted_bytes: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineSwitchPolicy {
    FailoverOnly,
    ActiveActiveRttRace,
    RoundRobin,
}

#[derive(Debug, Clone)]
pub struct DualBackendController {
    engines: HashMap<BackendEngineKind, EngineHealthMetric>,
    policy: EngineSwitchPolicy,
    active_engine: BackendEngineKind,
    round_robin_counter: usize,
}

impl DualBackendController {
    pub fn new(policy: EngineSwitchPolicy) -> Self {
        let mut engines = HashMap::new();
        engines.insert(BackendEngineKind::KcpRawSocket, EngineHealthMetric::default());
        engines.insert(BackendEngineKind::ViolatedTcpQuic, EngineHealthMetric::default());
        engines.insert(BackendEngineKind::FallbackStandard, EngineHealthMetric::default());

        Self {
            engines,
            policy,
            active_engine: BackendEngineKind::KcpRawSocket,
            round_robin_counter: 0,
        }
    }

    pub fn record_health(&mut self, engine: BackendEngineKind, rtt_ms: u32, loss_rate: f32, success: bool) {
        if let Some(m) = self.engines.get_mut(&engine) {
            m.rtt_ms = rtt_ms;
            m.packet_loss_rate = loss_rate;
            if success {
                m.consecutive_failures = 0;
                m.is_alive = true;
            } else {
                m.consecutive_failures += 1;
                if m.consecutive_failures >= 3 {
                    m.is_alive = false;
                }
            }
        }
    }

    pub fn record_bytes(&mut self, engine: BackendEngineKind, bytes: u64) {
        if let Some(m) = self.engines.get_mut(&engine) {
            m.total_transmitted_bytes += bytes;
        }
    }

    pub fn select_engine(&mut self) -> BackendEngineKind {
        match self.policy {
            EngineSwitchPolicy::FailoverOnly => {
                if let Some(m) = self.engines.get(&self.active_engine) {
                    if m.is_alive {
                        return self.active_engine;
                    }
                }
                // Failover search
                for &candidate in &[BackendEngineKind::KcpRawSocket, BackendEngineKind::ViolatedTcpQuic, BackendEngineKind::FallbackStandard] {
                    if let Some(m) = self.engines.get(&candidate) {
                        if m.is_alive {
                            self.active_engine = candidate;
                            return candidate;
                        }
                    }
                }
                BackendEngineKind::FallbackStandard
            }
            EngineSwitchPolicy::ActiveActiveRttRace => {
                let mut best_engine = BackendEngineKind::FallbackStandard;
                let mut lowest_score = f32::MAX;

                for (&engine, m) in &self.engines {
                    if m.is_alive {
                        // Weighted score: RTT + loss penalty
                        let score = (m.rtt_ms as f32) * (1.0 + m.packet_loss_rate * 2.0);
                        if score < lowest_score {
                            lowest_score = score;
                            best_engine = engine;
                        }
                    }
                }
                self.active_engine = best_engine;
                best_engine
            }
            EngineSwitchPolicy::RoundRobin => {
                let candidates = [BackendEngineKind::KcpRawSocket, BackendEngineKind::ViolatedTcpQuic];
                let chosen = candidates[self.round_robin_counter % candidates.len()];
                self.round_robin_counter += 1;
                if let Some(m) = self.engines.get(&chosen) {
                    if m.is_alive {
                        return chosen;
                    }
                }
                BackendEngineKind::FallbackStandard
            }
        }
    }

    pub fn get_health(&self, engine: BackendEngineKind) -> Option<&EngineHealthMetric> {
        self.engines.get(&engine)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failover_policy() {
        let mut controller = DualBackendController::new(EngineSwitchPolicy::FailoverOnly);
        assert_eq!(controller.select_engine(), BackendEngineKind::KcpRawSocket);

        // Fail KCP 3 times
        controller.record_health(BackendEngineKind::KcpRawSocket, 300, 0.5, false);
        controller.record_health(BackendEngineKind::KcpRawSocket, 300, 0.5, false);
        controller.record_health(BackendEngineKind::KcpRawSocket, 300, 0.5, false);

        // Should switch to ViolatedTcpQuic
        assert_eq!(controller.select_engine(), BackendEngineKind::ViolatedTcpQuic);
    }

    #[test]
    fn test_rtt_race_policy() {
        let mut controller = DualBackendController::new(EngineSwitchPolicy::ActiveActiveRttRace);
        controller.record_health(BackendEngineKind::KcpRawSocket, 150, 0.05, true);
        controller.record_health(BackendEngineKind::ViolatedTcpQuic, 45, 0.01, true);

        // ViolatedTcpQuic has much lower latency and loss
        assert_eq!(controller.select_engine(), BackendEngineKind::ViolatedTcpQuic);
    }

    #[test]
    fn test_round_robin() {
        let mut controller = DualBackendController::new(EngineSwitchPolicy::RoundRobin);
        let first = controller.select_engine();
        let second = controller.select_engine();
        assert_ne!(first, second);
    }
}
