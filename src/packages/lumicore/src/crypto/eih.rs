// Encrypted Inbound Header context for SS2022.
// Clean-room implementation. MIT License.

/// EIH context for encrypting/decrypting the inbound header of SS2022 sessions.
/// The EIH allows the server to determine the correct upstream destination
/// without decrypting the full payload.
///
#[derive(Clone)]
pub struct EihContext {
    /// Secondary key for EIH (separate from main session key).
    eih_key: Vec<u8>,
    /// Packet counter.
    nonce: u64,
}

impl EihContext {
    /// Create a new EIH context with the given key.
    pub fn new(eih_key: Vec<u8>) -> Self {
        Self { eih_key, nonce: 0 }
    }

    /// Encrypt the inbound header. Returns the encrypted payload with nonce prefix.
    pub fn encrypt_header(&self, payload: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut nonce_bytes = [0u8; 12];
        let nb = self.nonce.to_le_bytes();
        nonce_bytes[..8].copy_from_slice(&nb);

        // EIH encryption: XOR with key, then XOR with nonce bytes for variation.
        let mut out = Vec::with_capacity(12 + payload.len() + 16);
        out.write_all(&nonce_bytes).unwrap();
        for (i, &b) in payload.iter().enumerate() {
            let key_byte = self.eih_key[i % self.eih_key.len()];
            let nonce_byte = nonce_bytes[i % 12];
            out.write_all(&[b ^ key_byte ^ nonce_byte]).unwrap();
        }
        // In a full implementation the XOR above would be replaced by AES-GCM
        // or ChaCha20-Poly1305 authenticated encryption.
        out
    }

    /// Decrypt the inbound header. Returns the decrypted payload.
    pub fn decrypt_header(&self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() < 13 {
            return Err("ciphertext too short for EIH");
        }
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&ciphertext[..12]);

        let mut out = Vec::with_capacity(ciphertext.len() - 12);
        for (i, &b) in ciphertext[12..].iter().enumerate() {
            let key_byte = self.eih_key[i % self.eih_key.len()];
            let nonce_byte = nonce_bytes[i % 12];
            out.push(b ^ key_byte ^ nonce_byte);
        }
        Ok(out)
    }

    /// Increment the nonce for the next packet.
    pub fn next_packet(&mut self) {
        self.nonce = self.nonce.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eih_round_trip() {
        let ctx = EihContext::new(vec![0xAB; 32]);
        let payload = b"example.com";
        let ct = ctx.encrypt_header(payload);
        assert!(ct.len() > payload.len());
        let pt = ctx.decrypt_header(&ct).unwrap();
        assert_eq!(pt, payload);
    }
}
