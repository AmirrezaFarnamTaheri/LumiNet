//! # Camouflage Stream Masquerader & Active Probe Deflector
//!
//! Enforces active probe defense by validating obfuscated session preambles.
//! Unauthorized probes receive realistic HTTP/TLS decoys or are redirected to legitimate hosts.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeAction {
    AcceptStream,
    DeflectToDecoy,
    DropConnection,
}

pub struct CamouflageStreamMasquerader {
    shared_secret: Vec<u8>,
    valid_user_ids: Vec<[u8; 16]>,
    decoy_host: String,
}

impl CamouflageStreamMasquerader {
    pub fn new(shared_secret: &[u8], decoy_host: &str) -> Self {
        Self {
            shared_secret: shared_secret.to_vec(),
            valid_user_ids: Vec::new(),
            decoy_host: decoy_host.to_string(),
        }
    }

    pub fn register_user(&mut self, user_id: [u8; 16]) {
        self.valid_user_ids.push(user_id);
    }

    /// Generates client preamble: [16 bytes user_id] ^ [stream_key]
    pub fn generate_preamble(&self, user_id: [u8; 16]) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        // Salt (16 bytes)
        let salt = [0x5au8; 16];
        out.extend_from_slice(&salt);

        // Obfuscated user_id
        for i in 0..16 {
            let mask = self.shared_secret[i % self.shared_secret.len()] ^ salt[i];
            out.push(user_id[i] ^ mask);
        }
        out
    }

    /// Evaluates inbound stream preamble
    pub fn inspect_inbound_stream(&self, preamble: &[u8]) -> ProbeAction {
        if preamble.len() < 32 {
            return ProbeAction::DeflectToDecoy;
        }

        let salt = &preamble[0..16];
        let mut user_id = [0u8; 16];
        for i in 0..16 {
            let mask = self.shared_secret[i % self.shared_secret.len()] ^ salt[i];
            user_id[i] = preamble[16 + i] ^ mask;
        }

        if self.valid_user_ids.contains(&user_id) {
            ProbeAction::AcceptStream
        } else {
            ProbeAction::DeflectToDecoy
        }
    }

    pub fn decoy_host(&self) -> &str {
        &self.decoy_host
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_camouflage_stream_masquerader() {
        let secret = b"my_super_secret_seed";
        let mut masq = CamouflageStreamMasquerader::new(secret, "www.bing.com");
        let uid = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        masq.register_user(uid);

        let preamble = masq.generate_preamble(uid);
        assert_eq!(masq.inspect_inbound_stream(&preamble), ProbeAction::AcceptStream);

        // Invalid preamble
        let invalid_preamble = vec![0u8; 32];
        assert_eq!(
            masq.inspect_inbound_stream(&invalid_preamble),
            ProbeAction::DeflectToDecoy
        );
        assert_eq!(masq.decoy_host(), "www.bing.com");
    }
}
