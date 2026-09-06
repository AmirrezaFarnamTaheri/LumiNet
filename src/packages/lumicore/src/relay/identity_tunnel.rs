//! # Zero-Trust Identity-Bound Reverse Proxy Tunnel Header
//!
//! Encapsulates multiplexed reverse-proxy traffic over WireGuard tunnels with
//! a 16-byte session UUID, HMAC-SHA256 authentication tag, and stream metadata.

use sha2::{Digest, Sha256};

pub const IDENTITY_TUNNEL_MAGIC: [u8; 4] = [0x50, 0x41, 0x4E, 0x47]; // 'PANG'
pub const IDENTITY_TUNNEL_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityTunnelHeader {
    pub session_id: [u8; 16],
    pub stream_id: u32,
    pub flags: u8, // 0x01 = SYN, 0x02 = FIN, 0x04 = RST, 0x08 = PSH
    pub hmac_tag: [u8; 32],
    pub payload_len: u32,
}

impl IdentityTunnelHeader {
    pub fn new(session_id: [u8; 16], stream_id: u32, flags: u8, payload_len: u32, secret_key: &[u8]) -> Self {
        let mut h = Self {
            session_id,
            stream_id,
            flags,
            hmac_tag: [0u8; 32],
            payload_len,
        };
        h.hmac_tag = h.compute_hmac(secret_key);
        h
    }

    fn compute_hmac(&self, secret_key: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(secret_key);
        hasher.update(&IDENTITY_TUNNEL_MAGIC);
        hasher.update(&[IDENTITY_TUNNEL_VERSION, self.flags]);
        hasher.update(&self.session_id);
        hasher.update(&self.stream_id.to_be_bytes());
        hasher.update(&self.payload_len.to_be_bytes());
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(58);
        buf.extend_from_slice(&IDENTITY_TUNNEL_MAGIC);
        buf.push(IDENTITY_TUNNEL_VERSION);
        buf.push(self.flags);
        buf.extend_from_slice(&self.session_id);
        buf.extend_from_slice(&self.stream_id.to_be_bytes());
        buf.extend_from_slice(&self.payload_len.to_be_bytes());
        buf.extend_from_slice(&self.hmac_tag);
        buf
    }

    pub fn deserialize(bytes: &[u8], secret_key: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 58 {
            return Err("Identity tunnel header buffer too short");
        }
        if bytes[0..4] != IDENTITY_TUNNEL_MAGIC {
            return Err("Invalid magic bytes in identity tunnel header");
        }
        if bytes[4] != IDENTITY_TUNNEL_VERSION {
            return Err("Unsupported identity tunnel header version");
        }
        let flags = bytes[5];
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&bytes[6..22]);

        let mut stream_id_bytes = [0u8; 4];
        stream_id_bytes.copy_from_slice(&bytes[22..26]);
        let stream_id = u32::from_be_bytes(stream_id_bytes);

        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&bytes[26..30]);
        let payload_len = u32::from_be_bytes(len_bytes);

        let mut hmac_tag = [0u8; 32];
        hmac_tag.copy_from_slice(&bytes[30..62]);

        let hdr = Self {
            session_id,
            stream_id,
            flags,
            hmac_tag,
            payload_len,
        };

        let expected_hmac = hdr.compute_hmac(secret_key);
        if hdr.hmac_tag != expected_hmac {
            return Err("Identity tunnel header HMAC verification failed");
        }

        Ok(hdr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_tunnel_codec() {
        let key = b"super_secret_shared_key_1234567";
        let session = [0xABu8; 16];
        let hdr = IdentityTunnelHeader::new(session, 101, 0x01, 1024, key);
        let bytes = hdr.serialize();
        assert_eq!(bytes.len(), 62);

        let parsed = IdentityTunnelHeader::deserialize(&bytes, key).unwrap();
        assert_eq!(parsed.session_id, session);
        assert_eq!(parsed.stream_id, 101);
        assert_eq!(parsed.payload_len, 1024);

        // Invalid key
        assert!(IdentityTunnelHeader::deserialize(&bytes, b"wrong_key").is_err());
    }
}
