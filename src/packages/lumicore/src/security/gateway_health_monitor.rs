use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum GatewayState {
    Online,
    Degraded,
    Offline,
}

#[derive(Debug, Clone)]
pub struct GatewayMetric {
    pub gateway_ip: String,
    pub latency_ms: f64,
    pub packet_loss_ratio: f64,
    pub state: GatewayState,
}

#[derive(Debug, Default)]
pub struct GatewayHealthMonitor {
    gateways: HashMap<String, GatewayMetric>,
    loss_threshold_degraded: f64,
    loss_threshold_offline: f64,
}

impl GatewayHealthMonitor {
    pub fn new() -> Self {
        Self {
            gateways: HashMap::new(),
            loss_threshold_degraded: 0.20,
            loss_threshold_offline: 0.50,
        }
    }

    pub fn register_gateway(&mut self, ip: &str) {
        self.gateways.insert(ip.to_string(), GatewayMetric {
            gateway_ip: ip.to_string(),
            latency_ms: 0.0,
            packet_loss_ratio: 0.0,
            state: GatewayState::Online,
        });
    }

    pub fn record_probe(&mut self, ip: &str, latency_ms: f64, loss: f64) {
        if let Some(gw) = self.gateways.get_mut(ip) {
            gw.latency_ms = latency_ms;
            gw.packet_loss_ratio = loss;
            gw.state = if loss >= self.loss_threshold_offline {
                GatewayState::Offline
            } else if loss >= self.loss_threshold_degraded {
                GatewayState::Degraded
            } else {
                GatewayState::Online
            };
        }
    }

    pub fn select_active_gateway<'a>(&'a self, primary_ip: &'a str, backup_ip: &'a str) -> &'a str {
        if let Some(primary) = self.gateways.get(primary_ip) {
            if primary.state == GatewayState::Online {
                return primary_ip;
            }
        }
        if let Some(backup) = self.gateways.get(backup_ip) {
            if backup.state != GatewayState::Offline {
                return backup_ip;
            }
        }
        primary_ip
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gateway_health_failover() {
        let mut monitor = GatewayHealthMonitor::new();
        monitor.register_gateway("192.0.2.1"); // primary
        monitor.register_gateway("192.0.2.2"); // backup

        // Both healthy -> primary selected
        monitor.record_probe("192.0.2.1", 10.0, 0.0);
        monitor.record_probe("192.0.2.2", 15.0, 0.0);
        assert_eq!(monitor.select_active_gateway("192.0.2.1", "192.0.2.2"), "192.0.2.1");

        // Primary drops 60% packets -> offline -> failover to backup
        monitor.record_probe("192.0.2.1", 100.0, 0.60);
        assert_eq!(monitor.select_active_gateway("192.0.2.1", "192.0.2.2"), "192.0.2.2");
    }
}
