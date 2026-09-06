//! Asynchronous TCP Rendezvous Connection Bridge
//!
//! Pairs inbound client sessions with outbound egress agents across NAT/firewall
//! barriers via unique session tokens without direct external port mapping.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeSessionStatus {
    WaitingForAgent,
    WaitingForClient,
    Paired,
    Closed,
}

#[derive(Debug, Clone)]
pub struct BridgeSession {
    pub token: String,
    pub status: BridgeSessionStatus,
    pub client_addr: Option<String>,
    pub agent_addr: Option<String>,
    pub created_at_unix: u64,
}

#[derive(Debug, Default)]
pub struct TcpRendezvousBridge {
    sessions: HashMap<String, BridgeSession>,
}

impl TcpRendezvousBridge {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    pub fn register_client(&mut self, token: &str, client_addr: &str, now_unix: u64) -> BridgeSessionStatus {
        if let Some(session) = self.sessions.get_mut(token) {
            session.client_addr = Some(client_addr.to_string());
            if session.agent_addr.is_some() {
                session.status = BridgeSessionStatus::Paired;
            } else {
                session.status = BridgeSessionStatus::WaitingForAgent;
            }
            session.status.clone()
        } else {
            let session = BridgeSession {
                token: token.to_string(),
                status: BridgeSessionStatus::WaitingForAgent,
                client_addr: Some(client_addr.to_string()),
                agent_addr: None,
                created_at_unix: now_unix,
            };
            self.sessions.insert(token.to_string(), session);
            BridgeSessionStatus::WaitingForAgent
        }
    }

    pub fn register_agent(&mut self, token: &str, agent_addr: &str, now_unix: u64) -> BridgeSessionStatus {
        if let Some(session) = self.sessions.get_mut(token) {
            session.agent_addr = Some(agent_addr.to_string());
            if session.client_addr.is_some() {
                session.status = BridgeSessionStatus::Paired;
            } else {
                session.status = BridgeSessionStatus::WaitingForClient;
            }
            session.status.clone()
        } else {
            let session = BridgeSession {
                token: token.to_string(),
                status: BridgeSessionStatus::WaitingForClient,
                client_addr: None,
                agent_addr: Some(agent_addr.to_string()),
                created_at_unix: now_unix,
            };
            self.sessions.insert(token.to_string(), session);
            BridgeSessionStatus::WaitingForClient
        }
    }

    pub fn close_session(&mut self, token: &str) {
        if let Some(session) = self.sessions.get_mut(token) {
            session.status = BridgeSessionStatus::Closed;
        }
    }

    pub fn get_session(&self, token: &str) -> Option<&BridgeSession> {
        self.sessions.get(token)
    }

    pub fn active_session_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| s.status == BridgeSessionStatus::Paired)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rendezvous_pairing() {
        let mut bridge = TcpRendezvousBridge::new();
        let s1 = bridge.register_client("tok-1", "127.0.0.1:50000", 100);
        assert_eq!(s1, BridgeSessionStatus::WaitingForAgent);

        let s2 = bridge.register_agent("tok-1", "192.168.1.50:40000", 101);
        assert_eq!(s2, BridgeSessionStatus::Paired);
        assert_eq!(bridge.active_session_count(), 1);

        bridge.close_session("tok-1");
        assert_eq!(bridge.get_session("tok-1").unwrap().status, BridgeSessionStatus::Closed);
    }
}
