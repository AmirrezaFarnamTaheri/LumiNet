//! Tunnel Process Supervisor and Auto-Restart Watchdog
//!
//! Tracks child tunnel core processes, heartbeats, and restart quotas with
//! exponential backoff.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessStatus {
    Running,
    Stopped,
    Crashed,
    Backoff,
}

#[derive(Debug, Clone)]
pub struct MonitoredProcess {
    pub name: String,
    pub pid: Option<u32>,
    pub status: ProcessStatus,
    pub restart_count: u32,
    pub last_restart_unix: u64,
    pub backoff_delay_secs: u64,
}

#[derive(Debug, Default)]
pub struct TunnelProcessSupervisor {
    processes: HashMap<String, MonitoredProcess>,
    max_restarts: u32,
    base_backoff_secs: u64,
}

impl TunnelProcessSupervisor {
    pub fn new(max_restarts: u32, base_backoff_secs: u64) -> Self {
        Self {
            processes: HashMap::new(),
            max_restarts,
            base_backoff_secs: base_backoff_secs.max(1),
        }
    }

    pub fn register_process(&mut self, name: &str, pid: u32) {
        self.processes.insert(
            name.to_string(),
            MonitoredProcess {
                name: name.to_string(),
                pid: Some(pid),
                status: ProcessStatus::Running,
                restart_count: 0,
                last_restart_unix: 0,
                backoff_delay_secs: self.base_backoff_secs,
            },
        );
    }

    pub fn record_crash(&mut self, name: &str, now_unix: u64) -> bool {
        if let Some(proc) = self.processes.get_mut(name) {
            proc.pid = None;
            proc.restart_count += 1;
            proc.last_restart_unix = now_unix;

            if proc.restart_count > self.max_restarts {
                proc.status = ProcessStatus::Crashed;
                false
            } else {
                proc.status = ProcessStatus::Backoff;
                proc.backoff_delay_secs = (self.base_backoff_secs * (1 << (proc.restart_count - 1))).min(300);
                true
            }
        } else {
            false
        }
    }

    pub fn can_restart(&self, name: &str, now_unix: u64) -> bool {
        if let Some(proc) = self.processes.get(name) {
            if proc.status == ProcessStatus::Backoff {
                now_unix >= proc.last_restart_unix + proc.backoff_delay_secs
            } else {
                false
            }
        } else {
            false
        }
    }

    pub fn confirm_restart(&mut self, name: &str, new_pid: u32) {
        if let Some(proc) = self.processes.get_mut(name) {
            proc.pid = Some(new_pid);
            proc.status = ProcessStatus::Running;
        }
    }

    pub fn get_process(&self, name: &str) -> Option<&MonitoredProcess> {
        self.processes.get(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_supervisor_backoff() {
        let mut sup = TunnelProcessSupervisor::new(3, 5);
        sup.register_process("core-singbox", 1234);

        assert!(sup.record_crash("core-singbox", 100));
        assert!(!sup.can_restart("core-singbox", 104));
        assert!(sup.can_restart("core-singbox", 105));

        sup.confirm_restart("core-singbox", 1235);
        assert_eq!(sup.get_process("core-singbox").unwrap().status, ProcessStatus::Running);
    }
}
