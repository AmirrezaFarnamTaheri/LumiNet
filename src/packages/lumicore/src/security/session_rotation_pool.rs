//! # Credential Session Rotation Pool
//!
//! Rotates service account credentials, applies concurrency and query limits,
//! enforces lockout cooldown periods, and marks locked or rate-limited accounts.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountStatus {
    Ready,
    InUse,
    CoolingDown,
    Locked,
}

#[derive(Debug, Clone)]
pub struct ManagedAccount {
    pub account_id: String,
    pub token: String,
    pub uses_count: u32,
    pub max_uses: u32,
    pub status: AccountStatus,
    pub cooldown_until_sec: u64,
}

pub struct SessionRotationPool {
    accounts: HashMap<String, ManagedAccount>,
    rotation_order: Vec<String>,
    cursor: usize,
    default_cooldown_sec: u64,
}

impl SessionRotationPool {
    pub fn new(default_cooldown_sec: u64) -> Self {
        Self {
            accounts: HashMap::new(),
            rotation_order: Vec::new(),
            cursor: 0,
            default_cooldown_sec,
        }
    }

    pub fn add_account(&mut self, account_id: &str, token: &str, max_uses: u32) {
        self.accounts.insert(
            account_id.to_string(),
            ManagedAccount {
                account_id: account_id.to_string(),
                token: token.to_string(),
                uses_count: 0,
                max_uses,
                status: AccountStatus::Ready,
                cooldown_until_sec: 0,
            },
        );
        self.rotation_order.push(account_id.to_string());
    }

    pub fn acquire_account(&mut self, now_sec: u64) -> Option<(String, String)> {
        let n = self.rotation_order.len();
        if n == 0 {
            return None;
        }

        // First, check cooldowns
        for acc in self.accounts.values_mut() {
            if acc.status == AccountStatus::CoolingDown && now_sec >= acc.cooldown_until_sec {
                acc.status = AccountStatus::Ready;
                acc.uses_count = 0;
            }
        }

        for _ in 0..n {
            let id = self.rotation_order[self.cursor % n].clone();
            self.cursor += 1;

            if let Some(acc) = self.accounts.get_mut(&id) {
                if acc.status == AccountStatus::Ready {
                    acc.uses_count += 1;
                    if acc.uses_count >= acc.max_uses {
                        acc.status = AccountStatus::CoolingDown;
                        acc.cooldown_until_sec = now_sec + self.default_cooldown_sec;
                    }
                    return Some((acc.account_id.clone(), acc.token.clone()));
                }
            }
        }
        None
    }

    pub fn mark_locked(&mut self, account_id: &str) {
        if let Some(acc) = self.accounts.get_mut(account_id) {
            acc.status = AccountStatus::Locked;
        }
    }

    pub fn available_count(&self, now_sec: u64) -> usize {
        self.accounts
            .values()
            .filter(|a| {
                a.status == AccountStatus::Ready
                    || (a.status == AccountStatus::CoolingDown && now_sec >= a.cooldown_until_sec)
            })
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_rotation_and_cooldown() {
        let mut pool = SessionRotationPool::new(60);
        pool.add_account("acc1", "token1", 2);
        pool.add_account("acc2", "token2", 1);

        // Uses acc1 (1/2)
        let (id1, _) = pool.acquire_account(100).unwrap();
        assert_eq!(id1, "acc1");

        // Uses acc2 (1/1) -> cools down
        let (id2, _) = pool.acquire_account(100).unwrap();
        assert_eq!(id2, "acc2");

        // Uses acc1 (2/2) -> cools down
        let (id3, _) = pool.acquire_account(100).unwrap();
        assert_eq!(id3, "acc1");

        // Now both in cooldown at t=100
        assert_eq!(pool.acquire_account(100), None);

        // At t=161, cooldown passed
        assert!(pool.acquire_account(161).is_some());
    }
}
