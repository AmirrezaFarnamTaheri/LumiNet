//! TLS Session Obfuscator, Active Probing Passthrough Deflector, and ECH Draft-18 Parser
//!
//! Ported and unified from `psiphon-tls-master`.
//! Provides TLS session ticket padding to standard server profile distributions,
//! active-probing passthrough deflection routing, and Encrypted Client Hello (ECH) config parsing.

use std::fmt;

/// Canonical TLS session ticket padding bucket sizes matching typical server distributions.
pub const CANONICAL_PADDED_TICKET_SIZES: [usize; 8] = [160, 176, 192, 208, 218, 224, 240, 255];

/// Utilities for padding session tickets to defeat TLS fingerprinting.
pub struct TicketPadder;

impl TicketPadder {
    /// Pads a raw TLS session ticket with trailing zeros to match a standard distribution size.
    pub fn pad_ticket(ticket: &[u8]) -> Vec<u8> {
        let current_len = ticket.len();
        let target_size = if let Some(&size) = CANONICAL_PADDED_TICKET_SIZES.iter().find(|&&s| s >= current_len) {
            size
        } else {
            // If already larger than 255 bytes, pad to the next 16-byte boundary
            (current_len + 15) & !15
        };

        let mut out = Vec::with_capacity(target_size);
        out.extend_from_slice(ticket);
        out.resize(target_size, 0x00);
        out
    }

    /// Strips trailing padding zeros from an obfuscated session ticket.
    pub fn unpad_ticket(padded: &[u8]) -> &[u8] {
        let mut end = padded.len();
        while end > 0 && padded[end - 1] == 0x00 {
            end -= 1;
        }
        &padded[..end]
    }
}

/// Obfuscated client session state for session resumption without fingerprintable artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObfuscatedClientSessionState {
    pub ticket: Vec<u8>,
    pub version: u16,
    pub cipher_suite: u16,
    pub master_secret: Vec<u8>,
    pub created_at: u64,
    pub age_add: u32,
    pub use_by: u64,
}

impl ObfuscatedClientSessionState {
    pub fn new(
        ticket: &[u8],
        version: u16,
        cipher_suite: u16,
        master_secret: &[u8],
        created_at: u64,
        age_add: u32,
        use_by: u64,
    ) -> Self {
        Self {
            ticket: TicketPadder::pad_ticket(ticket),
            version,
            cipher_suite,
            master_secret: master_secret.to_vec(),
            created_at,
            age_add,
            use_by,
        }
    }

    /// Serializes session state into a structured byte payload.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.ticket.len() + self.master_secret.len());
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.cipher_suite.to_be_bytes());
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out.extend_from_slice(&self.age_add.to_be_bytes());
        out.extend_from_slice(&self.use_by.to_be_bytes());

        // Master secret
        out.extend_from_slice(&(self.master_secret.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.master_secret);

        // Ticket
        out.extend_from_slice(&(self.ticket.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.ticket);
        out
    }

    /// Deserializes session state from a byte slice.
    pub fn deserialize(buf: &[u8]) -> Result<Self, TlsObfuscatorError> {
        if buf.len() < 28 {
            return Err(TlsObfuscatorError::BufferTooShort);
        }

        let version = u16::from_be_bytes([buf[0], buf[1]]);
        let cipher_suite = u16::from_be_bytes([buf[2], buf[3]]);
        let created_at = u64::from_be_bytes([buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]]);
        let age_add = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let use_by = u64::from_be_bytes([buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23]]);

        let secret_len = u16::from_be_bytes([buf[24], buf[25]]) as usize;
        let mut offset = 26;
        if buf.len() < offset + secret_len + 2 {
            return Err(TlsObfuscatorError::BufferTooShort);
        }

        let master_secret = buf[offset..offset + secret_len].to_vec();
        offset += secret_len;

        let ticket_len = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
        offset += 2;
        if buf.len() < offset + ticket_len {
            return Err(TlsObfuscatorError::BufferTooShort);
        }

        let ticket = buf[offset..offset + ticket_len].to_vec();

        Ok(Self {
            ticket,
            version,
            cipher_suite,
            master_secret,
            created_at,
            age_add,
            use_by,
        })
    }
}

/// Active probing passthrough deflector.
/// Evaluates whether an incoming connection should be handled or forwarded to a fallback server.
#[derive(Debug, Clone)]
pub struct TlsPassthroughDeflector {
    pub passthrough_address: Option<String>,
    pub authorized_tokens: Vec<String>,
}

impl TlsPassthroughDeflector {
    pub fn new(passthrough_address: Option<String>, authorized_tokens: Vec<String>) -> Self {
        Self {
            passthrough_address,
            authorized_tokens,
        }
    }

    /// Evaluates whether connection credentials authorize direct tunnel termination or deflection.
    pub fn should_deflect(&self, presented_token: Option<&str>) -> bool {
        if self.passthrough_address.is_none() {
            return false;
        }

        match presented_token {
            Some(tok) => !self.authorized_tokens.iter().any(|t| t == tok),
            None => true,
        }
    }
}

/// Parsed Encrypted Client Hello (ECH) symmetric cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchCipher {
    pub kdf_id: u16,
    pub aead_id: u16,
}

/// Parsed ECH configuration entry from ECHConfigList.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchConfig {
    pub version: u16,
    pub config_id: u8,
    pub kem_id: u16,
    pub public_key: Vec<u8>,
    pub cipher_suites: Vec<EchCipher>,
    pub max_name_length: u8,
    pub public_name: String,
}

/// Parser for draft-ietf-tls-esni-18 ECHConfigList wire format.
pub struct EchConfigParser;

impl EchConfigParser {
    /// Parses an ECHConfigList binary byte slice.
    pub fn parse_config_list(data: &[u8]) -> Result<Vec<EchConfig>, TlsObfuscatorError> {
        if data.len() < 2 {
            return Err(TlsObfuscatorError::BufferTooShort);
        }

        let total_list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() != 2 + total_list_len {
            return Err(TlsObfuscatorError::MalformedEchConfigList);
        }

        let mut offset = 2;
        let mut configs = Vec::new();

        while offset < data.len() {
            if data.len() < offset + 4 {
                return Err(TlsObfuscatorError::MalformedEchConfigList);
            }

            let version = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let config_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if data.len() < offset + config_len {
                return Err(TlsObfuscatorError::MalformedEchConfigList);
            }

            let config_bytes = &data[offset..offset + config_len];
            offset += config_len;

            // Contents: config_id(1B), kem_id(2B), public_key_len(2B), public_key, cipher_suites_len(2B)...
            if config_bytes.len() < 5 {
                return Err(TlsObfuscatorError::MalformedEchConfigList);
            }

            let config_id = config_bytes[0];
            let kem_id = u16::from_be_bytes([config_bytes[1], config_bytes[2]]);
            let pk_len = u16::from_be_bytes([config_bytes[3], config_bytes[4]]) as usize;
            let mut c_offset = 5;

            if config_bytes.len() < c_offset + pk_len + 2 {
                return Err(TlsObfuscatorError::MalformedEchConfigList);
            }
            let public_key = config_bytes[c_offset..c_offset + pk_len].to_vec();
            c_offset += pk_len;

            let ciphers_len = u16::from_be_bytes([config_bytes[c_offset], config_bytes[c_offset + 1]]) as usize;
            c_offset += 2;

            if config_bytes.len() < c_offset + ciphers_len + 1 {
                return Err(TlsObfuscatorError::MalformedEchConfigList);
            }

            let mut cipher_suites = Vec::new();
            let ciphers_end = c_offset + ciphers_len;
            while c_offset + 4 <= ciphers_end {
                let kdf_id = u16::from_be_bytes([config_bytes[c_offset], config_bytes[c_offset + 1]]);
                let aead_id = u16::from_be_bytes([config_bytes[c_offset + 2], config_bytes[c_offset + 3]]);
                cipher_suites.push(EchCipher { kdf_id, aead_id });
                c_offset += 4;
            }
            c_offset = ciphers_end;

            let max_name_length = config_bytes[c_offset];
            c_offset += 1;

            if config_bytes.len() < c_offset + 1 {
                return Err(TlsObfuscatorError::MalformedEchConfigList);
            }
            let name_len = config_bytes[c_offset] as usize;
            c_offset += 1;

            if config_bytes.len() < c_offset + name_len {
                return Err(TlsObfuscatorError::MalformedEchConfigList);
            }
            let public_name = String::from_utf8_lossy(&config_bytes[c_offset..c_offset + name_len]).to_string();

            configs.push(EchConfig {
                version,
                config_id,
                kem_id,
                public_key,
                cipher_suites,
                max_name_length,
                public_name,
            });
        }

        Ok(configs)
    }
}

/// Errors related to TLS obfuscation and ECH decoding.
#[derive(Debug, PartialEq, Eq)]
pub enum TlsObfuscatorError {
    BufferTooShort,
    MalformedEchConfigList,
    InvalidSessionTicket,
}

impl fmt::Display for TlsObfuscatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort => write!(f, "Buffer too short for parsing"),
            Self::MalformedEchConfigList => write!(f, "Malformed draft-ietf-tls-esni-18 ECHConfigList"),
            Self::InvalidSessionTicket => write!(f, "Invalid session ticket format"),
        }
    }
}

impl std::error::Error for TlsObfuscatorError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ticket_padding_and_unpadding() {
        let raw_ticket = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let padded = TicketPadder::pad_ticket(&raw_ticket);

        // Smallest canonical size >= 5 is 160
        assert_eq!(padded.len(), 160);
        assert_eq!(&padded[..5], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
        assert!(padded[5..].iter().all(|&b| b == 0));

        let unpadded = TicketPadder::unpad_ticket(&padded);
        assert_eq!(unpadded, raw_ticket.as_slice());

        // Test boundary at 170 bytes -> should pad to 176
        let raw_170 = vec![0x11; 170];
        let padded_176 = TicketPadder::pad_ticket(&raw_170);
        assert_eq!(padded_176.len(), 176);
        assert_eq!(TicketPadder::unpad_ticket(&padded_176), raw_170.as_slice());
    }

    #[test]
    fn test_obfuscated_session_state_roundtrip() {
        let ticket = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let secret = vec![0x42; 32];
        let state = ObfuscatedClientSessionState::new(
            &ticket,
            0x0304, // TLS 1.3
            0x1301, // TLS_AES_128_GCM_SHA256
            &secret,
            1710000000,
            12345,
            1710100000,
        );

        assert_eq!(state.ticket.len(), 160); // Padded to 160

        let serialized = state.serialize();
        let deserialized = ObfuscatedClientSessionState::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.version, 0x0304);
        assert_eq!(deserialized.cipher_suite, 0x1301);
        assert_eq!(deserialized.created_at, 1710000000);
        assert_eq!(deserialized.age_add, 12345);
        assert_eq!(deserialized.master_secret, secret);
        assert_eq!(TicketPadder::unpad_ticket(&deserialized.ticket), ticket.as_slice());
    }

    #[test]
    fn test_passthrough_deflector() {
        let deflector = TlsPassthroughDeflector::new(
            Some("192.0.2.1:443".into()),
            vec!["secret-auth-token-123".into()],
        );

        // Valid token -> do not deflect (terminate locally)
        assert!(!deflector.should_deflect(Some("secret-auth-token-123")));

        // Invalid token -> deflect to fallback server
        assert!(deflector.should_deflect(Some("invalid-probe-token")));

        // No token presented -> deflect
        assert!(deflector.should_deflect(None));

        // No passthrough configured -> never deflect
        let disabled_deflector = TlsPassthroughDeflector::new(None, vec![]);
        assert!(!disabled_deflector.should_deflect(None));
    }

    #[test]
    fn test_ech_config_list_parser() {
        // Construct synthetic ECHConfigList
        let mut config_body = Vec::new();
        config_body.push(0x01); // config_id = 1
        config_body.extend_from_slice(&0x0020u16.to_be_bytes()); // kem_id = DHKEM(X25519)
        config_body.extend_from_slice(&4u16.to_be_bytes()); // pk_len = 4
        config_body.extend_from_slice(&[0x10, 0x20, 0x30, 0x40]); // pk

        // Cipher suites
        config_body.extend_from_slice(&4u16.to_be_bytes()); // cipher len = 4
        config_body.extend_from_slice(&0x0001u16.to_be_bytes()); // kdf_id = HKDF_SHA256
        config_body.extend_from_slice(&0x0001u16.to_be_bytes()); // aead_id = AES_128_GCM

        config_body.push(64); // max_name_length
        let public_name = b"cloudflare-ech.com";
        config_body.push(public_name.len() as u8);
        config_body.extend_from_slice(public_name);

        let mut data = Vec::new();
        let total_config_len = config_body.len() as u16;
        let mut config_entry = Vec::new();
        config_entry.extend_from_slice(&0xfe0du16.to_be_bytes()); // version = draft-13/18 (0xfe0d)
        config_entry.extend_from_slice(&total_config_len.to_be_bytes());
        config_entry.extend_from_slice(&config_body);

        let list_len = config_entry.len() as u16;
        data.extend_from_slice(&list_len.to_be_bytes());
        data.extend_from_slice(&config_entry);

        let parsed_list = EchConfigParser::parse_config_list(&data).unwrap();
        assert_eq!(parsed_list.len(), 1);
        let ec = &parsed_list[0];
        assert_eq!(ec.version, 0xfe0d);
        assert_eq!(ec.config_id, 1);
        assert_eq!(ec.kem_id, 0x0020);
        assert_eq!(ec.public_key, vec![0x10, 0x20, 0x30, 0x40]);
        assert_eq!(ec.cipher_suites.len(), 1);
        assert_eq!(ec.cipher_suites[0].kdf_id, 1);
        assert_eq!(ec.public_name, "cloudflare-ech.com");
    }
}
