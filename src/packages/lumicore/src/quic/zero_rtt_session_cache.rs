//! QUIC and HTTP/3 0-RTT Session Ticket Cache and Anti-Replay Guard
//!
//! Stores TLS 1.3 / QUIC session resumption tickets, tracks active ALPNs,
//! and guards against replay attacks using a sliding bloom/nonce table.

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct SessionTicket {
    pub server_name: String,
    pub ticket_bytes: Vec<u8>,
    pub alpn: String,
    pub expires_at_unix: u64,
}

#[derive(Debug, Default)]
pub struct ZeroRttSessionCache {
    tickets: HashMap<String, SessionTicket>,
    consumed_nonces: HashSet<Vec<u8>>,
}

impl ZeroRttSessionCache {
    pub fn new() -> Self {
        Self {
            tickets: HashMap::new(),
            consumed_nonces: HashSet::new(),
        }
    }

    pub fn store_ticket(&mut self, server_name: &str, ticket_bytes: &[u8], alpn: &str, now: u64, ttl_secs: u64) {
        self.tickets.insert(
            server_name.to_lowercase(),
            SessionTicket {
                server_name: server_name.to_string(),
                ticket_bytes: ticket_bytes.to_vec(),
                alpn: alpn.to_string(),
                expires_at_unix: now + ttl_secs,
            },
        );
    }

    pub fn get_valid_ticket(&mut self, server_name: &str, now: u64) -> Option<SessionTicket> {
        let key = server_name.to_lowercase();
        if let Some(t) = self.tickets.get(&key) {
            if t.expires_at_unix > now {
                return Some(t.clone());
            }
        }
        self.tickets.remove(&key);
        None
    }

    /// Anti-replay guard: returns true if nonce is accepted (first seen), false if replayed
    pub fn check_and_consume_nonce(&mut self, nonce: &[u8]) -> bool {
        if self.consumed_nonces.contains(nonce) {
            false
        } else {
            self.consumed_nonces.insert(nonce.to_vec());
            true
        }
    }

    pub fn ticket_count(&self) -> usize {
        self.tickets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_rtt_ticket_lifecycle() {
        let mut cache = ZeroRttSessionCache::new();
        cache.store_ticket("edge.luminet.io", b"ticket-data", "h3", 1000, 300);

        let valid = cache.get_valid_ticket("edge.luminet.io", 1100).unwrap();
        assert_eq!(valid.ticket_bytes, b"ticket-data");
        assert_eq!(valid.alpn, "h3");

        // Expired
        let expired = cache.get_valid_ticket("edge.luminet.io", 1301);
        assert!(expired.is_none());

        // Anti-replay nonce test
        let nonce = b"nonce-123456";
        assert!(cache.check_and_consume_nonce(nonce));
        assert!(!cache.check_and_consume_nonce(nonce)); // duplicate rejected
    }
}
