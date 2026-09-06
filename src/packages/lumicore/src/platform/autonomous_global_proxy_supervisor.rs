// Pure Rust implementation: Autonomous Global Proxy Supervisor (Batch 10 Synthesis C2)
// Unifies and orchestrates all 147 Wave 2 absorbed subsystems into an autonomous multi-plane core.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct SubsystemHealth {
    pub name: String,
    pub plane: &'static str,
    pub is_healthy: bool,
    pub active_connections: u32,
    pub last_heartbeat_ms: u64,
    pub error_msg: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GlobalSystemReport {
    pub total_subsystems: usize,
    pub healthy_subsystems: usize,
    pub health_percentage: f32,
    pub total_active_connections: u32,
    pub killswitch_engaged: bool,
}

pub struct AutonomousGlobalProxySupervisor {
    pub subsystems: HashMap<String, SubsystemHealth>,
    pub killswitch_engaged: bool,
    pub auto_remediation_enabled: bool,
}

impl AutonomousGlobalProxySupervisor {
    pub fn new(auto_remediation: bool) -> Self {
        Self {
            subsystems: HashMap::new(),
            killswitch_engaged: false,
            auto_remediation_enabled: auto_remediation,
        }
    }

    pub fn register_subsystem(&mut self, name: impl Into<String>, plane: &'static str) {
        let n = name.into();
        self.subsystems.insert(
            n.clone(),
            SubsystemHealth {
                name: n,
                plane,
                is_healthy: true,
                active_connections: 0,
                last_heartbeat_ms: 0,
                error_msg: None,
            },
        );
    }

    pub fn update_health(
        &mut self,
        name: &str,
        is_healthy: bool,
        active_connections: u32,
        now_ms: u64,
        error_msg: Option<String>,
    ) -> bool {
        if let Some(sub) = self.subsystems.get_mut(name) {
            sub.is_healthy = is_healthy;
            sub.active_connections = active_connections;
            sub.last_heartbeat_ms = now_ms;
            sub.error_msg = error_msg;
            true
        } else {
            false
        }
    }

    pub fn set_killswitch(&mut self, engaged: bool) {
        self.killswitch_engaged = engaged;
        if engaged {
            // Terminate active connections across all subsystems
            for sub in self.subsystems.values_mut() {
                sub.active_connections = 0;
            }
        }
    }

    pub fn generate_global_report(&self) -> GlobalSystemReport {
        let total = self.subsystems.len();
        let healthy = self.subsystems.values().filter(|s| s.is_healthy).count();
        let active_conns = self.subsystems.values().map(|s| s.active_connections).sum();
        let health_pct = if total == 0 {
            100.0
        } else {
            (healthy as f32 / total as f32) * 100.0
        };

        GlobalSystemReport {
            total_subsystems: total,
            healthy_subsystems: healthy,
            health_percentage: health_pct,
            total_active_connections: active_conns,
            killswitch_engaged: self.killswitch_engaged,
        }
    }

    pub fn identify_remediation_targets(&self, now_ms: u64, stale_timeout_ms: u64) -> Vec<String> {
        if !self.auto_remediation_enabled {
            return Vec::new();
        }

        self.subsystems
            .values()
            .filter(|s| {
                !s.is_healthy
                    || (now_ms.saturating_sub(s.last_heartbeat_ms) > stale_timeout_ms
                        && s.last_heartbeat_ms > 0)
            })
            .map(|s| s.name.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_supervisor_report_and_killswitch() {
        let mut supervisor = AutonomousGlobalProxySupervisor::new(true);
        supervisor.register_subsystem("mesh_wireguard_coordinator", "routing");
        supervisor.register_subsystem("on_device_dpi_evader", "evasion");
        supervisor.register_subsystem("multiprotocol_traffic_inspector", "transport");

        supervisor.update_health("mesh_wireguard_coordinator", true, 15, 1000, None);
        supervisor.update_health("on_device_dpi_evader", true, 25, 1000, None);
        supervisor.update_health("multiprotocol_traffic_inspector", false, 0, 1000, Some("Port conflict".to_string()));

        let report = supervisor.generate_global_report();
        assert_eq!(report.total_subsystems, 3);
        assert_eq!(report.healthy_subsystems, 2);
        assert!((report.health_percentage - 66.666).abs() < 1.0);
        assert_eq!(report.total_active_connections, 40);

        // Killswitch drops all active connections
        supervisor.set_killswitch(true);
        let post_kill = supervisor.generate_global_report();
        assert_eq!(post_kill.total_active_connections, 0);
        assert!(post_kill.killswitch_engaged);
    }

    #[test]
    fn test_auto_remediation_detection() {
        let mut supervisor = AutonomousGlobalProxySupervisor::new(true);
        supervisor.register_subsystem("core_engine_supervisor", "platform");
        supervisor.update_health("core_engine_supervisor", false, 0, 1000, Some("Out of memory".to_string()));

        let targets = supervisor.identify_remediation_targets(2000, 5000);
        assert_eq!(targets, vec!["core_engine_supervisor".to_string()]);
    }
}
