//! # Mobile Engine Provider
//!
//! Mobile proxy core engine controller for Android/embedded platforms, providing
//! lifecycle management, state transitions, runtime telemetry, and tun2socks supervisor hooks.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EngineState {
    Stopped,
    Starting,
    Running,
    Degraded,
    Stopping,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineMetrics {
    pub uptime_secs: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub active_tunnels: u32,
    pub last_heartbeat: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    pub bind_address: String,
    pub socks5_port: u16,
    pub http_port: u16,
    pub dns_port: u16,
    pub mtu: u32,
    pub enable_ipv6: bool,
}

pub struct MobileEngineProvider {
    config: EngineConfig,
    state: EngineState,
    metrics: EngineMetrics,
    start_timestamp: u64,
}

impl MobileEngineProvider {
    pub fn new(config: EngineConfig) -> Self {
        Self {
            config,
            state: EngineState::Stopped,
            metrics: EngineMetrics {
                uptime_secs: 0,
                rx_bytes: 0,
                tx_bytes: 0,
                active_tunnels: 0,
                last_heartbeat: 0,
            },
            start_timestamp: 0,
        }
    }

    pub fn start_engine(&mut self, timestamp: u64) -> Result<(), String> {
        if self.state == EngineState::Running {
            return Err("Engine is already running".to_string());
        }
        if self.config.socks5_port == 0 || self.config.http_port == 0 {
            self.state = EngineState::Error;
            return Err("Invalid port configuration".to_string());
        }

        self.state = EngineState::Starting;
        self.start_timestamp = timestamp;
        self.metrics.last_heartbeat = timestamp;
        self.metrics.active_tunnels = 1;
        self.state = EngineState::Running;
        Ok(())
    }

    pub fn stop_engine(&mut self) -> Result<(), String> {
        if self.state == EngineState::Stopped {
            return Ok(());
        }
        self.state = EngineState::Stopping;
        self.metrics.active_tunnels = 0;
        self.state = EngineState::Stopped;
        Ok(())
    }

    pub fn record_traffic(&mut self, rx: u64, tx: u64, timestamp: u64) {
        self.metrics.rx_bytes += rx;
        self.metrics.tx_bytes += tx;
        self.metrics.last_heartbeat = timestamp;
        if self.start_timestamp > 0 && timestamp >= self.start_timestamp {
            self.metrics.uptime_secs = timestamp - self.start_timestamp;
        }
    }

    pub fn mark_degraded(&mut self, degraded: bool) {
        if self.state == EngineState::Running && degraded {
            self.state = EngineState::Degraded;
        } else if self.state == EngineState::Degraded && !degraded {
            self.state = EngineState::Running;
        }
    }

    pub fn get_state(&self) -> EngineState {
        self.state
    }

    pub fn get_metrics(&self) -> &EngineMetrics {
        &self.metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_lifecycle_and_telemetry() {
        let config = EngineConfig {
            bind_address: "127.0.0.1".to_string(),
            socks5_port: 10808,
            http_port: 10809,
            dns_port: 5353,
            mtu: 1500,
            enable_ipv6: false,
        };

        let mut provider = MobileEngineProvider::new(config);
        assert_eq!(provider.get_state(), EngineState::Stopped);

        provider.start_engine(1000).unwrap();
        assert_eq!(provider.get_state(), EngineState::Running);

        provider.record_traffic(1024, 2048, 1050);
        let m = provider.get_metrics();
        assert_eq!(m.rx_bytes, 1024);
        assert_eq!(m.tx_bytes, 2048);
        assert_eq!(m.uptime_secs, 50);

        provider.mark_degraded(true);
        assert_eq!(provider.get_state(), EngineState::Degraded);

        provider.stop_engine().unwrap();
        assert_eq!(provider.get_state(), EngineState::Stopped);
    }
}
