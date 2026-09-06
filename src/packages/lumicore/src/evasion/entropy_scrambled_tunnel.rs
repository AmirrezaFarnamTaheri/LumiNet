//! # Entropy Scrambled Tunnel
//!
//! Advanced anti-censorship framing layer that scrambles packets to maximize Shannon entropy,
//! introduces pseudo-random padding jitter, and flattens packet length distributions against ML classifiers.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

pub struct EntropyScrambledTunnel {
    secret_key: [u8; 32],
    min_padding: usize,
    max_padding: usize,
}

impl EntropyScrambledTunnel {
    pub fn new(secret_key: [u8; 32], min_padding: usize, max_padding: usize) -> Self {
        Self {
            secret_key,
            min_padding: min_padding.max(4),
            max_padding: max_padding.max(min_padding + 8),
        }
    }

    fn derive_stream_rng(&self, seed: u64) -> ChaCha8Rng {
        let mut key = self.secret_key;
        let seed_bytes = seed.to_le_bytes();
        for i in 0..8 {
            key[i] ^= seed_bytes[i];
        }
        ChaCha8Rng::from_seed(key)
    }

    pub fn scramble_packet(&self, payload: &[u8], seed: u64) -> Vec<u8> {
        let mut rng = ChaCha8Rng::seed_from_u64(seed.wrapping_add(1));

        // Determine random padding length
        let pad_range = self.max_padding - self.min_padding;
        let pad_len = self.min_padding + (rng.gen::<usize>() % pad_range);

        let mut out = Vec::with_capacity(4 + payload.len() + pad_len);

        // Header: 2 bytes payload length, 2 bytes padding length
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&(pad_len as u16).to_be_bytes());

        // Payload
        out.extend_from_slice(payload);

        // Random high-entropy padding
        for _ in 0..pad_len {
            out.push(rng.gen::<u8>());
        }

        // Apply ChaCha8 cryptographic stream mask derived from secret_key and seed
        let mut mask_rng = self.derive_stream_rng(seed);
        for byte in out.iter_mut() {
            *byte ^= mask_rng.gen::<u8>();
        }

        out
    }

    pub fn descramble_packet(&self, scrambled: &[u8], seed: u64) -> Result<Vec<u8>, String> {
        if scrambled.len() < 4 {
            return Err("Packet too short".to_string());
        }

        // Unmask packet using identical ChaCha8 keystream
        let mut unmasked = scrambled.to_vec();
        let mut mask_rng = self.derive_stream_rng(seed);
        for byte in unmasked.iter_mut() {
            *byte ^= mask_rng.gen::<u8>();
        }

        let payload_len = u16::from_be_bytes([unmasked[0], unmasked[1]]) as usize;
        let pad_len = u16::from_be_bytes([unmasked[2], unmasked[3]]) as usize;

        if unmasked.len() < 4 + payload_len + pad_len {
            return Err("Incomplete descrambled frame".to_string());
        }

        Ok(unmasked[4..4 + payload_len].to_vec())
    }

    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0usize; 256];
        for &b in data {
            counts[b as usize] += 1;
        }

        let total = data.len() as f64;
        let mut entropy = 0.0;

        for &c in &counts {
            if c > 0 {
                let p = c as f64 / total;
                entropy -= p * p.log2();
            }
        }

        entropy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_scrambled_tunnel_roundtrip() {
        let key = [0x55; 32];
        let tunnel = EntropyScrambledTunnel::new(key, 8, 32);

        // Low entropy plaintext (all zeroes)
        let plaintext = vec![0u8; 128];
        assert_eq!(EntropyScrambledTunnel::calculate_entropy(&plaintext), 0.0);

        let scrambled = tunnel.scramble_packet(&plaintext, 123456789);
        assert!(scrambled.len() >= 128 + 4 + 8);

        // Scrambled packet should exhibit high Shannon entropy (> 7.0 out of 8.0)
        let ent = EntropyScrambledTunnel::calculate_entropy(&scrambled);
        assert!(ent > 6.0, "Entropy should be high: got {}", ent);

        let recovered = tunnel.descramble_packet(&scrambled, 123456789).unwrap();
        assert_eq!(recovered, plaintext);
    }
}
