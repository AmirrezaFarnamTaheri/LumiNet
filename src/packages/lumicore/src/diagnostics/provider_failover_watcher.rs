//! # Provider Failover Watcher & Heartbeat Tracker
//!
//! Tracks proxy provider health, detects consecutive connection or auth failures,
//! and initiates automated failover to alternate standby providers.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderStatus {
    Operational,
    Unstable,
    Failed,
}

#[derive(Debug, Clone)]
pub struct ProviderHealth {
    pub provider_name: String,
    pub consecutive_failures: u32,
    pub successful_heartbeats: u64,
    pub last_latency_ms: u32,
    pub status: ProviderStatus,
}

pub struct ProviderFailoverWatcher {
    providers: HashMap<String, ProviderHealth>,
    failover_threshold: u32,
    active_provider: Option<String>,
}

impl ProviderFailoverWatcher {
    pub fn new(failover_threshold: u32) -> Self {
        Self {
            providers: HashMap::new(),
            failover_threshold: failover_threshold.max(1),
            active_provider: None,
        }
    }

    pub fn register_provider(&mut self, name: &str, is_active: bool) {
        self.providers.insert(
            name.to_string(),
            ProviderHealth {
                provider_name: name.to_string(),
                consecutive_failures: 0,
                successful_heartbeats: 0,
                last_latency_ms: 0,
                status: ProviderStatus::Operational,
            },
        );
        if is_active {
            self.active_provider = Some(name.to_string());
        }
    }

    pub fn record_heartbeat(&mut self, name: &str, latency_ms: u32, success: bool) -> Option<String> {
        let (needs_failover, current_name) = match self.providers.get_mut(name) {
            Some(p) => {
                if success {
                    p.consecutive_failures = 0;
                    p.successful_heartbeats += 1;
                    p.last_latency_ms = latency_ms;
                    p.status = ProviderStatus::Operational;
                    (false, p.provider_name.clone())
                } else {
                    p.consecutive_failures += 1;
                    if p.consecutive_failures >= self.failover_threshold {
                        p.status = ProviderStatus::Failed;
                        (true, p.provider_name.clone())
                    } else {
                        p.status = ProviderStatus::Unstable;
                        (false, p.provider_name.clone())
                    }
                }
            }
            None => return None,
        };

        if needs_failover && self.active_provider.as_ref() == Some(&current_name) {
            self.failover_to_next()
        } else {
            None
        }
    }

    pub fn failover_to_next(&mut self) -> Option<String> {
        let candidate = self
            .providers
            .values()
            .find(|p| p.status == ProviderStatus::Operational && Some(&p.provider_name) != self.active_provider.as_ref())
            .map(|p| p.provider_name.clone());

        if let Some(ref next_p) = candidate {
            self.active_provider = Some(next_p.clone());
        }
        candidate
    }

    pub fn active_provider(&self) -> Option<&str> {
        self.active_provider.as_deref()
    }

    pub fn get_health(&self, name: &str) -> Option<&ProviderHealth> {
        self.providers.get(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_failover_trigger() {
        let mut watcher = ProviderFailoverWatcher::new(3);
        watcher.register_provider("primary-vpn", true);
        watcher.register_provider("standby-vpn", false);

        assert_eq!(watcher.active_provider(), Some("primary-vpn"));

        // 2 failures -> unstable
        watcher.record_heartbeat("primary-vpn", 500, false);
        watcher.record_heartbeat("primary-vpn", 500, false);
        assert_eq!(watcher.get_health("primary-vpn").unwrap().status, ProviderStatus::Unstable);
        assert_eq!(watcher.active_provider(), Some("primary-vpn"));

        // 3rd failure -> triggers failover to standby
        let failover = watcher.record_heartbeat("primary-vpn", 500, false);
        assert_eq!(failover, Some("standby-vpn".to_string()));
        assert_eq!(watcher.active_provider(), Some("standby-vpn"));
        assert_eq!(watcher.get_health("primary-vpn").unwrap().status, ProviderStatus::Failed);
    }
}
