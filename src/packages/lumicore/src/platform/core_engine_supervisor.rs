// Pure Rust implementation: Core Engine Lifecycle Supervisor

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineState {
    Stopped,
    Starting,
    Running,
    Degraded,
    Crashed(String),
}

#[derive(Debug, Clone)]
pub struct EngineMetrics {
    pub pid: u32,
    pub uptime_seconds: u64,
    pub memory_rss_bytes: u64,
    pub restart_count: u32,
}

#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    pub binary_name: String,
    pub max_restarts: u32,
    pub restart_cooldown_ms: u64,
    pub memory_limit_bytes: u64,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            binary_name: "lumicore-engine".to_string(),
            max_restarts: 5,
            restart_cooldown_ms: 3000,
            memory_limit_bytes: 256 * 1024 * 1024, // 256 MB
        }
    }
}

pub struct CoreEngineSupervisor {
    pub config: SupervisorConfig,
    pub state: EngineState,
    pub metrics: EngineMetrics,
}

impl CoreEngineSupervisor {
    pub fn new(config: SupervisorConfig) -> Self {
        Self {
            config,
            state: EngineState::Stopped,
            metrics: EngineMetrics {
                pid: 0,
                uptime_seconds: 0,
                memory_rss_bytes: 0,
                restart_count: 0,
            },
        }
    }

    pub fn start(&mut self, simulated_pid: u32) -> Result<(), String> {
        if self.state == EngineState::Running {
            return Err("Engine is already running".to_string());
        }

        self.state = EngineState::Starting;
        self.metrics.pid = simulated_pid;
        self.metrics.uptime_seconds = 0;
        self.state = EngineState::Running;
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), String> {
        self.state = EngineState::Stopped;
        self.metrics.pid = 0;
        Ok(())
    }

    pub fn handle_process_exit(&mut self, exit_code: i32) -> EngineState {
        if exit_code == 0 {
            self.state = EngineState::Stopped;
            self.metrics.pid = 0;
        } else {
            self.metrics.restart_count += 1;
            if self.metrics.restart_count > self.config.max_restarts {
                self.state = EngineState::Crashed(format!(
                    "Process exceeded max restarts ({}) with exit code {}",
                    self.config.max_restarts, exit_code
                ));
            } else {
                self.state = EngineState::Degraded;
            }
        }
        self.state.clone()
    }

    pub fn record_heartbeat(&mut self, elapsed_secs: u64, current_rss_bytes: u64) -> Result<(), String> {
        if self.state != EngineState::Running && self.state != EngineState::Degraded {
            return Err("Cannot record heartbeat on inactive engine".to_string());
        }

        self.metrics.uptime_seconds += elapsed_secs;
        self.metrics.memory_rss_bytes = current_rss_bytes;

        if current_rss_bytes > self.config.memory_limit_bytes {
            self.state = EngineState::Degraded;
            return Err(format!(
                "Memory limit exceeded: {} > {}",
                current_rss_bytes, self.config.memory_limit_bytes
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_and_heartbeat() {
        let mut supervisor = CoreEngineSupervisor::new(SupervisorConfig::default());
        assert_eq!(supervisor.state, EngineState::Stopped);

        supervisor.start(12345).unwrap();
        assert_eq!(supervisor.state, EngineState::Running);
        assert_eq!(supervisor.metrics.pid, 12345);

        // Valid heartbeat
        assert!(supervisor.record_heartbeat(5, 50 * 1024 * 1024).is_ok());
        assert_eq!(supervisor.metrics.uptime_seconds, 5);

        // Exceed memory limit
        let res = supervisor.record_heartbeat(5, 300 * 1024 * 1024);
        assert!(res.is_err());
        assert_eq!(supervisor.state, EngineState::Degraded);
    }

    #[test]
    fn test_exit_and_crash_recovery() {
        let mut config = SupervisorConfig::default();
        config.max_restarts = 2;
        let mut supervisor = CoreEngineSupervisor::new(config);

        supervisor.start(100).unwrap();
        assert_eq!(supervisor.handle_process_exit(1), EngineState::Degraded);
        assert_eq!(supervisor.metrics.restart_count, 1);

        supervisor.start(101).unwrap();
        assert_eq!(supervisor.handle_process_exit(1), EngineState::Degraded);
        assert_eq!(supervisor.metrics.restart_count, 2);

        // 3rd crash exceeds max restarts of 2
        supervisor.start(102).unwrap();
        let state = supervisor.handle_process_exit(1);
        match state {
            EngineState::Crashed(_) => {}
            other => panic!("Expected Crashed, got {:?}", other),
        }
    }
}
