//! Multi-Socket Connection Pool Supervisor and Failover Manager
//!
//! Maintains a warm pool of virtual proxy sockets with health scoring,
//! automated ping heartbeats, and hot standby automatic failover.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketState {
    Active,
    Standby,
    Degraded,
    Dead,
}

#[derive(Debug, Clone)]
pub struct ManagedSocket {
    pub id: String,
    pub endpoint: String,
    pub state: SocketState,
    pub consecutive_failures: u32,
    pub last_rtt_ms: u64,
}

#[derive(Debug, Default)]
pub struct SocketPoolSupervisor {
    sockets: HashMap<String, ManagedSocket>,
    active_socket_id: Option<String>,
}

impl SocketPoolSupervisor {
    pub fn new() -> Self {
        Self {
            sockets: HashMap::new(),
            active_socket_id: None,
        }
    }

    pub fn register_socket(&mut self, id: &str, endpoint: &str) {
        let is_first = self.sockets.is_empty();
        let state = if is_first { SocketState::Active } else { SocketState::Standby };
        if is_first {
            self.active_socket_id = Some(id.to_string());
        }
        self.sockets.insert(
            id.to_string(),
            ManagedSocket {
                id: id.to_string(),
                endpoint: endpoint.to_string(),
                state,
                consecutive_failures: 0,
                last_rtt_ms: 0,
            },
        );
    }

    pub fn record_heartbeat(&mut self, id: &str, rtt_ms: u64, success: bool) {
        if let Some(sock) = self.sockets.get_mut(id) {
            sock.last_rtt_ms = rtt_ms;
            if success {
                sock.consecutive_failures = 0;
                if sock.state == SocketState::Degraded {
                    sock.state = SocketState::Standby;
                }
            } else {
                sock.consecutive_failures += 1;
                if sock.consecutive_failures >= 3 {
                    sock.state = SocketState::Dead;
                } else {
                    sock.state = SocketState::Degraded;
                }
            }
        }

        // Trigger failover if active socket died or degraded
        if let Some(ref active) = self.active_socket_id.clone() {
            if active == id && !success {
                self.elect_new_active();
            }
        }
    }

    fn elect_new_active(&mut self) {
        let mut best: Option<(String, u64)> = None;
        for (id, s) in &self.sockets {
            if s.state == SocketState::Standby {
                if let Some((_, best_rtt)) = best {
                    if s.last_rtt_ms < best_rtt {
                        best = Some((id.clone(), s.last_rtt_ms));
                    }
                } else {
                    best = Some((id.clone(), s.last_rtt_ms));
                }
            }
        }

        if let Some((best_id, _)) = best {
            if let Some(prev) = self.active_socket_id.take() {
                if let Some(prev_sock) = self.sockets.get_mut(&prev) {
                    if prev_sock.state == SocketState::Active {
                        prev_sock.state = SocketState::Standby;
                    }
                }
            }
            if let Some(new_active) = self.sockets.get_mut(&best_id) {
                new_active.state = SocketState::Active;
            }
            self.active_socket_id = Some(best_id);
        }
    }

    pub fn active_socket(&self) -> Option<&ManagedSocket> {
        self.active_socket_id.as_ref().and_then(|id| self.sockets.get(id))
    }

    pub fn socket_count(&self) -> usize {
        self.sockets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_pool_failover() {
        let mut pool = SocketPoolSupervisor::new();
        pool.register_socket("sock-primary", "1.1.1.1:443");
        pool.register_socket("sock-backup", "2.2.2.2:443");

        assert_eq!(pool.active_socket().unwrap().id, "sock-primary");

        // Primary fails
        pool.record_heartbeat("sock-primary", 999, false);
        assert_eq!(pool.active_socket().unwrap().id, "sock-backup");
    }
}
