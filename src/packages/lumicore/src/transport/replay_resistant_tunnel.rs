//! # Replay-Resistant Tunnel Session
//!
//! Authenticated proxy tunnel session protocol preventing packet replay attacks
//! through sliding nonce tracking, monotonic sequence validation, and HKDF session key derivation.

use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct ReplayResistantConfig {
    pub psk: Vec<u8>,
    pub max_skew_secs: u64,
    pub max_tracked_nonces: usize,
}

impl Default for ReplayResistantConfig {
    fn default() -> Self {
        Self {
            psk: b"luminet-default-replay-psk-2026".to_vec(),
            max_skew_secs: 60,
            max_tracked_nonces: 4096,
        }
    }
}

pub struct ReplayResistantTunnelSession {
    config: ReplayResistantConfig,
    session_key: Vec<u8>,
    last_remote_seq: u64,
    seen_nonces: HashSet<[u8; 12]>,
}

impl ReplayResistantTunnelSession {
    pub fn new(config: ReplayResistantConfig, client_random: &[u8], server_random: &[u8]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(client_random), &config.psk);
        let mut session_key = vec![0u8; 32];
        hk.expand(server_random, &mut session_key)
            .expect("32 bytes is valid length for HKDF-SHA256");

        Self {
            config,
            session_key,
            last_remote_seq: 0,
            seen_nonces: HashSet::new(),
        }
    }

    pub fn seal_packet(&self, sequence: u64, timestamp: u64, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(8 + 8 + 12 + payload.len() + 16);
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&timestamp.to_be_bytes());

        // Derive deterministic nonce from sequence, timestamp, and session_key
        let mut nonce = [0u8; 12];
        let seq_bytes = sequence.to_be_bytes();
        let ts_bytes = timestamp.to_be_bytes();
        for i in 0..8 {
            nonce[i] = seq_bytes[i] ^ self.session_key[i];
        }
        for i in 0..4 {
            nonce[8 + i] = ts_bytes[i] ^ self.session_key[8 + i];
        }
        packet.extend_from_slice(&nonce);

        // XOR payload with session stream
        for (i, byte) in payload.iter().enumerate() {
            let k = self.session_key[(i + nonce[i % 12] as usize) % self.session_key.len()];
            packet.push(byte ^ k);
        }

        // 16-byte MAC tag over packet
        let hk = Hkdf::<Sha256>::new(Some(&nonce), &self.session_key);
        let mut tag = [0u8; 16];
        hk.expand(&packet, &mut tag).expect("16 bytes valid");
        packet.extend_from_slice(&tag);

        packet
    }

    pub fn open_packet(
        &mut self,
        packet: &[u8],
        current_time: u64,
    ) -> Result<(u64, u64, Vec<u8>), String> {
        if packet.len() < 8 + 8 + 12 + 16 {
            return Err("Packet smaller than replay envelope minimum".to_string());
        }

        let seq_bytes: [u8; 8] = packet[0..8].try_into().unwrap();
        let sequence = u64::from_be_bytes(seq_bytes);

        let ts_bytes: [u8; 8] = packet[8..16].try_into().unwrap();
        let timestamp = u64::from_be_bytes(ts_bytes);

        // Validate timestamp skew
        let diff = if current_time >= timestamp {
            current_time - timestamp
        } else {
            timestamp - current_time
        };
        if diff > self.config.max_skew_secs {
            return Err(format!("Timestamp skew too large: {}s", diff));
        }

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&packet[16..28]);

        // Check replay via nonce cache
        if self.seen_nonces.contains(&nonce) {
            return Err("Replay detected: duplicate nonce".to_string());
        }

        // Verify MAC
        let body_end = packet.len() - 16;
        let provided_tag = &packet[body_end..];
        let hk = Hkdf::<Sha256>::new(Some(&nonce), &self.session_key);
        let mut expected_tag = [0u8; 16];
        hk.expand(&packet[..body_end], &mut expected_tag).expect("16 bytes valid");
        if provided_tag != expected_tag {
            return Err("Integrity verification failed".to_string());
        }

        // Sequence monotonicity check
        if sequence <= self.last_remote_seq && self.last_remote_seq > 0 {
            return Err(format!(
                "Out of order / replayed sequence: got {}, last {}",
                sequence, self.last_remote_seq
            ));
        }

        // Decrypt payload
        let enc_payload = &packet[28..body_end];
        let mut decrypted = Vec::with_capacity(enc_payload.len());
        for (i, byte) in enc_payload.iter().enumerate() {
            let k = self.session_key[(i + nonce[i % 12] as usize) % self.session_key.len()];
            decrypted.push(byte ^ k);
        }

        // Commit nonce and sequence
        if self.seen_nonces.len() >= self.config.max_tracked_nonces {
            self.seen_nonces.clear();
        }
        self.seen_nonces.insert(nonce);
        self.last_remote_seq = sequence;

        Ok((sequence, timestamp, decrypted))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_and_open_success() {
        let config = ReplayResistantConfig::default();
        let client_rand = b"client_nonce_123456";
        let server_rand = b"server_nonce_abcdef";

        let sender = ReplayResistantTunnelSession::new(config.clone(), client_rand, server_rand);
        let mut receiver = ReplayResistantTunnelSession::new(config, client_rand, server_rand);

        let now = 1700000000;
        let sealed = sender.seal_packet(1, now, b"authenticated message");

        let (seq, ts, payload) = receiver.open_packet(&sealed, now + 2).unwrap();
        assert_eq!(seq, 1);
        assert_eq!(ts, now);
        assert_eq!(payload, b"authenticated message");
    }

    #[test]
    fn test_replay_rejection() {
        let config = ReplayResistantConfig::default();
        let client_rand = b"client_nonce_123456";
        let server_rand = b"server_nonce_abcdef";

        let sender = ReplayResistantTunnelSession::new(config.clone(), client_rand, server_rand);
        let mut receiver = ReplayResistantTunnelSession::new(config, client_rand, server_rand);

        let now = 1700000000;
        let sealed = sender.seal_packet(1, now, b"packet one");

        assert!(receiver.open_packet(&sealed, now).is_ok());
        // Replaying same packet should fail
        let replay_err = receiver.open_packet(&sealed, now);
        assert!(replay_err.is_err());
    }

    #[test]
    fn test_skew_timeout_rejection() {
        let config = ReplayResistantConfig::default();
        let client_rand = b"client_nonce_123456";
        let server_rand = b"server_nonce_abcdef";

        let sender = ReplayResistantTunnelSession::new(config.clone(), client_rand, server_rand);
        let mut receiver = ReplayResistantTunnelSession::new(config, client_rand, server_rand);

        let now = 1700000000;
        let sealed = sender.seal_packet(1, now, b"packet one");

        // 120 seconds later (max skew is 60)
        let res = receiver.open_packet(&sealed, now + 120);
        assert!(res.is_err());
    }
}
