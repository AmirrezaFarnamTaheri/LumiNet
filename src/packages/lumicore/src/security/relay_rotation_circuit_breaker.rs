// Pure Rust implementation: Relay Rotation Circuit Breaker

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug, Clone)]
pub struct RelayNode {
    pub id: String,
    pub endpoint: String,
    pub consecutive_failures: u32,
    pub successful_probes: u32,
    pub state: CircuitState,
    pub last_state_change_ms: u64,
}

#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub half_open_probes_needed: u32,
    pub cooldown_ms: u64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            half_open_probes_needed: 2,
            cooldown_ms: 30_000,
        }
    }
}

pub struct RelayRotationCircuitBreaker {
    pub config: CircuitBreakerConfig,
    pub relays: Vec<RelayNode>,
    pub current_index: usize,
}

impl RelayRotationCircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            relays: Vec::new(),
            current_index: 0,
        }
    }

    pub fn register_relay(&mut self, id: impl Into<String>, endpoint: impl Into<String>) {
        self.relays.push(RelayNode {
            id: id.into(),
            endpoint: endpoint.into(),
            consecutive_failures: 0,
            successful_probes: 0,
            state: CircuitState::Closed,
            last_state_change_ms: 0,
        });
    }

    pub fn select_active_relay(&mut self, now_ms: u64) -> Option<String> {
        if self.relays.is_empty() {
            return None;
        }

        let total = self.relays.len();
        for _ in 0..total {
            let idx = self.current_index % total;
            let relay = &mut self.relays[idx];

            // Check if Open state has cooled down -> transition to HalfOpen
            if relay.state == CircuitState::Open {
                if now_ms.saturating_sub(relay.last_state_change_ms) >= self.config.cooldown_ms {
                    relay.state = CircuitState::HalfOpen;
                    relay.successful_probes = 0;
                    relay.last_state_change_ms = now_ms;
                    return Some(relay.id.clone());
                }
            } else {
                // Closed or HalfOpen is eligible
                return Some(relay.id.clone());
            }

            self.current_index = (self.current_index + 1) % total;
        }

        None
    }

    pub fn record_success(&mut self, id: &str, now_ms: u64) {
        if let Some(relay) = self.relays.iter_mut().find(|r| r.id == id) {
            relay.consecutive_failures = 0;
            if relay.state == CircuitState::HalfOpen {
                relay.successful_probes += 1;
                if relay.successful_probes >= self.config.half_open_probes_needed {
                    relay.state = CircuitState::Closed;
                    relay.last_state_change_ms = now_ms;
                }
            }
        }
    }

    pub fn record_failure(&mut self, id: &str, now_ms: u64) {
        let mut should_advance = false;
        if let Some(relay) = self.relays.iter_mut().find(|r| r.id == id) {
            relay.consecutive_failures += 1;
            match relay.state {
                CircuitState::Closed => {
                    if relay.consecutive_failures >= self.config.failure_threshold {
                        relay.state = CircuitState::Open;
                        relay.last_state_change_ms = now_ms;
                        should_advance = true;
                    }
                }
                CircuitState::HalfOpen => {
                    // Any failure in HalfOpen resets to Open immediately
                    relay.state = CircuitState::Open;
                    relay.last_state_change_ms = now_ms;
                    should_advance = true;
                }
                CircuitState::Open => {}
            }
        }

        if should_advance && !self.relays.is_empty() {
            self.current_index = (self.current_index + 1) % self.relays.len();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_circuit_trip_and_recovery() {
        let mut cb = RelayRotationCircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 2,
            half_open_probes_needed: 2,
            cooldown_ms: 10_000,
        });

        cb.register_relay("relay-1", "1.1.1.1:443");
        cb.register_relay("relay-2", "2.2.2.2:443");

        // First relay active
        assert_eq!(cb.select_active_relay(1000), Some("relay-1".to_string()));

        // 2 consecutive failures trip relay-1 to Open
        cb.record_failure("relay-1", 1100);
        cb.record_failure("relay-1", 1200);

        // Active relay should now rotate to relay-2
        assert_eq!(cb.select_active_relay(1300), Some("relay-2".to_string()));

        // Fail relay-2 as well
        cb.record_failure("relay-2", 1300);
        cb.record_failure("relay-2", 1300);

        // After cooldown (10,000ms), relay-1 should transition to HalfOpen
        assert_eq!(cb.select_active_relay(12_000), Some("relay-1".to_string()));
        assert_eq!(cb.relays[0].state, CircuitState::HalfOpen);

        // 2 successful probes restore to Closed
        cb.record_success("relay-1", 12_100);
        cb.record_success("relay-1", 12_200);
        assert_eq!(cb.relays[0].state, CircuitState::Closed);
    }
}
