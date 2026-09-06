//! Inbound Client Rate Limiter and Suspicious IP Ban Supervisor
//!
//! Tracks authentication failures, rate of unexpected connection closures,
//! and enforces token-bucket limits with temporary quarantine bans.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessStatus {
    Allowed,
    Throttled,
    Banned { remaining_secs: u64 },
}

#[derive(Debug, Clone)]
struct ClientRecord {
    failure_count: u32,
    tokens: f64,
    last_access_unix: u64,
    banned_until_unix: u64,
}

#[derive(Debug)]
pub struct ClientBanSupervisor {
    clients: HashMap<String, ClientRecord>,
    max_failures: u32,
    ban_duration_secs: u64,
    bucket_capacity: f64,
    refill_rate_per_sec: f64,
}

impl Default for ClientBanSupervisor {
    fn default() -> Self {
        Self::new(5, 300, 10.0, 1.0)
    }
}

impl ClientBanSupervisor {
    pub fn new(max_failures: u32, ban_duration_secs: u64, capacity: f64, refill_rate: f64) -> Self {
        Self {
            clients: HashMap::new(),
            max_failures,
            ban_duration_secs,
            bucket_capacity: capacity,
            refill_rate_per_sec: refill_rate,
        }
    }

    /// Evaluates an incoming connection and updates token bucket & ban status
    pub fn check_access(&mut self, ip: &str, now: u64) -> AccessStatus {
        let client = self.clients.entry(ip.to_string()).or_insert_with(|| ClientRecord {
            failure_count: 0,
            tokens: self.bucket_capacity,
            last_access_unix: now,
            banned_until_unix: 0,
        });

        // Check if currently banned
        if client.banned_until_unix > now {
            return AccessStatus::Banned {
                remaining_secs: client.banned_until_unix - now,
            };
        }

        // Refill tokens
        let elapsed = (now.saturating_sub(client.last_access_unix)) as f64;
        client.tokens = (client.tokens + elapsed * self.refill_rate_per_sec).min(self.bucket_capacity);
        client.last_access_unix = now;

        if client.tokens < 1.0 {
            AccessStatus::Throttled
        } else {
            client.tokens -= 1.0;
            AccessStatus::Allowed
        }
    }

    /// Records authentication or handshake outcome
    pub fn record_auth_result(&mut self, ip: &str, success: bool, now: u64) {
        if let Some(client) = self.clients.get_mut(ip) {
            if success {
                client.failure_count = 0;
            } else {
                client.failure_count += 1;
                if client.failure_count >= self.max_failures {
                    client.banned_until_unix = now + self.ban_duration_secs;
                }
            }
        }
    }

    pub fn unban(&mut self, ip: &str) {
        if let Some(client) = self.clients.get_mut(ip) {
            client.banned_until_unix = 0;
            client.failure_count = 0;
        }
    }

    pub fn is_banned(&self, ip: &str, now: u64) -> bool {
        if let Some(client) = self.clients.get(ip) {
            client.banned_until_unix > now
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ban_after_failures() {
        let mut sup = ClientBanSupervisor::new(3, 60, 10.0, 1.0);
        let ip = "198.51.100.25";

        assert_eq!(sup.check_access(ip, 100), AccessStatus::Allowed);

        // Failures
        sup.record_auth_result(ip, false, 100);
        sup.record_auth_result(ip, false, 101);
        assert!(!sup.is_banned(ip, 101));

        sup.record_auth_result(ip, false, 102); // 3rd failure triggers ban
        assert!(sup.is_banned(ip, 102));

        match sup.check_access(ip, 103) {
            AccessStatus::Banned { remaining_secs } => assert_eq!(remaining_secs, 59),
            _ => panic!("Expected banned status"),
        }

        // Unban
        sup.unban(ip);
        assert!(!sup.is_banned(ip, 104));
    }
}
