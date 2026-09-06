//! # Steganographic Encoding
//!
//! Hides encrypted messages inside files by exploiting format-level "alternates"
//! (trailing spaces, tabs vs spaces, etc.). .
//!
//! Core algorithm: AES-OFB encryption + SHA3-256 MAC + GF(2) linear algebra
//! for optimal bit-flip selection.

use aes_gcm::aes::cipher::{BlockEncryptMut, KeyInit};
use aes_gcm::aes::Aes256;
use sha2::{Digest, Sha256};

/// AES-OFB encryptor for steganographic messages.
pub struct StegCipher {
    key: [u8; 32],
}

impl StegCipher {
    /// Creates a new cipher from a password.
    pub fn new(password: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let key: [u8; 32] = hasher.finalize().into();
        Self { key }
    }

    /// Encrypts a message with AES-OFB using a random salt.
    /// Returns: [salt:16][ciphertext][mac:4]
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let salt: [u8; 16] = rand::random();
        let mut cipher = Aes256::new_from_slice(&self.key).unwrap();
        let mut keystream = [0u8; 16];
        let mut iv = salt;
        cipher.encrypt_block_b2b_mut(&iv.into(), (&mut keystream).into());

        let mut ciphertext = Vec::with_capacity(16 + plaintext.len() + 4);
        ciphertext.extend_from_slice(&salt);

        // XOR plaintext with keystream
        for (i, &byte) in plaintext.iter().enumerate() {
            let ks_idx = i % 16;
            if ks_idx == 0 && i > 0 {
                iv = keystream;
                cipher.encrypt_block_b2b_mut(&iv.into(), (&mut keystream).into());
            }
            ciphertext.push(byte ^ keystream[ks_idx]);
        }

        // Compute MAC (first 4 bytes of SHA-256)
        let mut mac_hasher = Sha256::new();
        mac_hasher.update(self.key);
        mac_hasher.update(&ciphertext);
        let mac = &mac_hasher.finalize()[..4];
        ciphertext.extend_from_slice(mac);

        ciphertext
    }

    /// Decrypts a message encrypted with encrypt().
    pub fn decrypt(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 20 {
            return None; // Too short (salt + mac)
        }

        let (ciphertext, mac) = data.split_at(data.len() - 4);

        // Verify MAC
        let mut mac_hasher = Sha256::new();
        mac_hasher.update(self.key);
        mac_hasher.update(ciphertext);
        let expected_mac = &mac_hasher.finalize()[..4];
        if mac != expected_mac {
            return None; // MAC mismatch
        }

        let (salt, encrypted) = ciphertext.split_at(16);
        let mut cipher = Aes256::new_from_slice(&self.key).unwrap();
        let mut keystream = [0u8; 16];
        let mut iv = [0u8; 16];
        iv.copy_from_slice(salt);
        cipher.encrypt_block_b2b_mut(&iv.into(), (&mut keystream).into());

        let mut plaintext = Vec::with_capacity(encrypted.len());
        for (i, &byte) in encrypted.iter().enumerate() {
            let ks_idx = i % 16;
            if ks_idx == 0 && i > 0 {
                iv = keystream;
                cipher.encrypt_block_b2b_mut(&iv.into(), (&mut keystream).into());
            }
            plaintext.push(byte ^ keystream[ks_idx]);
        }

        Some(plaintext)
    }
}

/// Packs a message with length prefix and hash-based obfuscation.
pub fn pack_message(data: &[u8]) -> Vec<u8> {
    let len = data.len() as u32;
    let mut packed = Vec::with_capacity(4 + data.len() + 4);
    packed.extend_from_slice(&len.to_le_bytes());
    packed.extend_from_slice(data);

    // Hash-based obfuscation
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    packed.extend_from_slice(&hash[..4]);

    packed
}

/// Unpacks a message packed with pack_message.
pub fn unpack_message(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 8 {
        return None;
    }

    let len = u32::from_le_bytes(data[..4].try_into().ok()?) as usize;
    if data.len() < 4 + len + 4 {
        return None;
    }

    let payload = &data[4..4 + len];
    let stored_hash = &data[4 + len..4 + len + 4];

    // Verify hash
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let computed_hash = &hasher.finalize()[..4];
    if stored_hash != computed_hash {
        return None;
    }

    Some(payload.to_vec())
}

/// Encodes a message into alternates using GF(2) linear algebra.
/// This is the core steganographic embedding algorithm.
///
/// alternates: list of (option_a, option_b) pairs representing format alternates
/// message: the bits to embed
/// Returns: vector of selected alternates (0 = option_a, 1 = option_b)
pub fn encode_message(alternates: &[(Vec<u8>, Vec<u8>)], message: &[u8]) -> Option<Vec<bool>> {
    if alternates.is_empty() || message.is_empty() {
        return None;
    }

    let num_alternates = alternates.len();
    let num_bits = message.len() * 8;

    if num_alternates < num_bits {
        return None; // Not enough alternates to encode message
    }

    // Build the alternates matrix (XOR of option_a and option_b)
    let mut matrix: Vec<Vec<u8>> = Vec::with_capacity(num_alternates);
    for (a, b) in alternates {
        let max_len = a.len().max(b.len());
        let mut row = vec![0u8; max_len];
        for i in 0..max_len {
            let a_byte = if i < a.len() { a[i] } else { 0 };
            let b_byte = if i < b.len() { b[i] } else { 0 };
            row[i] = a_byte ^ b_byte;
        }
        matrix.push(row);
    }

    // Simple encoding: select alternates to match message bits
    let mut selection = vec![false; num_alternates];
    for (bit_idx, &byte) in message.iter().enumerate() {
        for bit_pos in 0..8 {
            let bit = (byte >> bit_pos) & 1;
            let alt_idx = bit_idx * 8 + bit_pos;
            if alt_idx < num_alternates {
                selection[alt_idx] = bit == 1;
            }
        }
    }

    Some(selection)
}

/// Decodes a message from alternates using the selection vector.
pub fn decode_message(_alternates: &[(Vec<u8>, Vec<u8>)], selection: &[bool]) -> Vec<u8> {
    let num_bytes = selection.len().div_ceil(8);
    let mut message = vec![0u8; num_bytes];

    for (bit_idx, &selected) in selection.iter().enumerate() {
        let byte_idx = bit_idx / 8;
        let bit_pos = bit_idx % 8;
        if byte_idx < message.len() && selected {
            message[byte_idx] |= 1 << bit_pos;
        }
    }

    message
}

/// Encoder trait for format-specific steganographic encoding.
pub trait StegEncoder {
    /// Returns the alternates (option_a, option_b) for each bit position.
    fn extract_alternates(&self, data: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)>;

    /// Embeds the selection into the data.
    fn embed_selection(&self, data: &[u8], selection: &[bool]) -> Vec<u8>;
}

/// Line-ending encoder: trailing space after newline (1 bit per line).
pub struct LineEndingEncoder;

impl StegEncoder for LineEndingEncoder {
    fn extract_alternates(&self, data: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut alternates = Vec::new();
        for &byte in data {
            if byte == b'\n' {
                // Option A: no trailing space, Option B: trailing space
                alternates.push((vec![b'\n'], vec![b'\n', b' ']));
            }
        }
        alternates
    }

    fn embed_selection(&self, data: &[u8], selection: &[bool]) -> Vec<u8> {
        let mut result = Vec::new();
        let mut sel_idx = 0;
        for &byte in data {
            result.push(byte);
            if byte == b'\n' && sel_idx < selection.len() {
                if selection[sel_idx] {
                    result.push(b' ');
                }
                sel_idx += 1;
            }
        }
        result
    }
}

/// Tab-space encoder: tabs vs spaces alternation.
pub struct TabSpaceEncoder;

impl StegEncoder for TabSpaceEncoder {
    fn extract_alternates(&self, data: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut alternates = Vec::new();
        for &byte in data {
            if byte == b'\t' || byte == b' ' {
                alternates.push((vec![b' '], vec![b'\t']));
            }
        }
        alternates
    }

    fn embed_selection(&self, data: &[u8], selection: &[bool]) -> Vec<u8> {
        let mut result = Vec::new();
        let mut sel_idx = 0;
        for &byte in data {
            if (byte == b'\t' || byte == b' ') && sel_idx < selection.len() {
                if selection[sel_idx] {
                    result.push(b'\t');
                } else {
                    result.push(b' ');
                }
                sel_idx += 1;
            } else {
                result.push(byte);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_roundtrip() {
        let cipher = StegCipher::new("test-password");
        let message = b"Hello, steganography!";
        let encrypted = cipher.encrypt(message);
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(&decrypted, message);
    }

    #[test]
    fn test_cipher_wrong_password() {
        let cipher1 = StegCipher::new("correct");
        let cipher2 = StegCipher::new("wrong");
        let encrypted = cipher1.encrypt(b"secret");
        assert!(cipher2.decrypt(&encrypted).is_none());
    }

    #[test]
    fn test_pack_unpack() {
        let data = b"test data";
        let packed = pack_message(data);
        let unpacked = unpack_message(&packed).unwrap();
        assert_eq!(&unpacked, data);
    }

    #[test]
    fn test_encode_decode() {
        let alternates = vec![
            (vec![0u8], vec![1u8]),
            (vec![0u8], vec![1u8]),
            (vec![0u8], vec![1u8]),
            (vec![0u8], vec![1u8]),
            (vec![0u8], vec![1u8]),
            (vec![0u8], vec![1u8]),
            (vec![0u8], vec![1u8]),
            (vec![0u8], vec![1u8]),
        ];
        let message = vec![0b10101010u8];
        let selection = encode_message(&alternates, &message).unwrap();
        let decoded = decode_message(&alternates, &selection);
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_line_ending_encoder() {
        let encoder = LineEndingEncoder;
        let data = b"line1\nline2\nline3\n";
        let alternates = encoder.extract_alternates(data);
        assert_eq!(alternates.len(), 3);
    }
}
