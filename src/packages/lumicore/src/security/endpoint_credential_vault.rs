//! # Endpoint Credential Vault & Profile Store
//!
//! Provides isolated in-memory credential storage, per-endpoint profile binding,
//! and authenticated session token issuance with expiry.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct EndpointProfile {
    pub profile_id: String,
    pub server_host: String,
    pub server_port: u16,
    pub username: String,
    pub encrypted_secret: Vec<u8>,
    pub created_at_sec: u64,
    pub expires_at_sec: u64,
}

pub struct EndpointCredentialVault {
    profiles: HashMap<String, EndpointProfile>,
    master_key: [u8; 32],
}

impl EndpointCredentialVault {
    pub fn new(master_key: [u8; 32]) -> Self {
        Self {
            profiles: HashMap::new(),
            master_key,
        }
    }

    pub fn store_profile(
        &mut self,
        profile_id: &str,
        host: &str,
        port: u16,
        user: &str,
        raw_secret: &[u8],
        now_sec: u64,
        ttl_sec: u64,
    ) {
        let mut enc = raw_secret.to_vec();
        for (i, byte) in enc.iter_mut().enumerate() {
            *byte ^= self.master_key[i % 32];
        }

        self.profiles.insert(
            profile_id.to_string(),
            EndpointProfile {
                profile_id: profile_id.to_string(),
                server_host: host.to_string(),
                server_port: port,
                username: user.to_string(),
                encrypted_secret: enc,
                created_at_sec: now_sec,
                expires_at_sec: now_sec + ttl_sec,
            },
        );
    }

    pub fn retrieve_secret(&self, profile_id: &str, now_sec: u64) -> Option<Vec<u8>> {
        let p = self.profiles.get(profile_id)?;
        if now_sec > p.expires_at_sec {
            return None; // expired
        }
        let mut dec = p.encrypted_secret.clone();
        for (i, byte) in dec.iter_mut().enumerate() {
            *byte ^= self.master_key[i % 32];
        }
        Some(dec)
    }

    pub fn is_profile_valid(&self, profile_id: &str, now_sec: u64) -> bool {
        match self.profiles.get(profile_id) {
            Some(p) => now_sec <= p.expires_at_sec,
            None => false,
        }
    }

    pub fn purge_expired(&mut self, now_sec: u64) -> usize {
        let before = self.profiles.len();
        self.profiles.retain(|_, p| now_sec <= p.expires_at_sec);
        before - self.profiles.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_vault_encryption_and_expiry() {
        let key = [0x42; 32];
        let mut vault = EndpointCredentialVault::new(key);
        let secret = b"super-vpn-password-123";

        vault.store_profile("prof1", "vpn.example.com", 443, "alice", secret, 1000, 300);

        // Valid at t=1100
        assert!(vault.is_profile_valid("prof1", 1100));
        let retrieved = vault.retrieve_secret("prof1", 1100).unwrap();
        assert_eq!(retrieved, secret);

        // Expired at t=1301
        assert!(!vault.is_profile_valid("prof1", 1301));
        assert_eq!(vault.retrieve_secret("prof1", 1301), None);

        let purged = vault.purge_expired(1301);
        assert_eq!(purged, 1);
        assert_eq!(vault.is_profile_valid("prof1", 1100), false);
    }
}
