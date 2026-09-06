//! Tactical Tunnel Session & Obfuscator
//!
//! Provides tactical protocol negotiation, multi-stage obfuscated session framing,
//! dynamic tactics filtering based on network/GeoIP context, and bidirectional stream ciphering.
//!
//! Conforms to strict architectural isolation guidelines: zero vendor prefixes.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use sha1::{Digest, Sha1};

pub const OBFUSCATE_SEED_LENGTH: usize = 16;
pub const OBFUSCATE_KEY_LENGTH: usize = 16;
pub const OBFUSCATE_HASH_ITERATIONS: usize = 6000;
pub const OBFUSCATE_MAX_PADDING: usize = 8192;
pub const OBFUSCATE_MAGIC_VALUE: u32 = 0x0BF5_CA7E;
pub const OBFUSCATE_CLIENT_TO_SERVER_IV: &[u8] = b"client_to_server";
pub const OBFUSCATE_SERVER_TO_CLIENT_IV: &[u8] = b"server_to_client";
pub const PREAMBLE_HEADER_LENGTH: usize = OBFUSCATE_SEED_LENGTH + 8;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TacticalSessionError {
    InvalidSeedLength,
    InvalidMagic(u32),
    ExcessivePadding(usize),
    BufferTooShort,
    KeyDerivationFailed,
    ExpiredTactics,
    FilterMismatch,
}

impl std::fmt::Display for TacticalSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSeedLength => write!(f, "tactical session: invalid seed length"),
            Self::InvalidMagic(m) => write!(f, "tactical session: invalid magic header 0x{:08X}", m),
            Self::ExcessivePadding(n) => write!(f, "tactical session: padding size {} exceeds max {}", n, OBFUSCATE_MAX_PADDING),
            Self::BufferTooShort => write!(f, "tactical session: buffer too short for preamble framing"),
            Self::KeyDerivationFailed => write!(f, "tactical session: key derivation failed"),
            Self::ExpiredTactics => write!(f, "tactical session: tactics have expired"),
            Self::FilterMismatch => write!(f, "tactical session: network attributes did not match filter criteria"),
        }
    }
}

impl std::error::Error for TacticalSessionError {}

/// Standard RC4 stream cipher state for tactical stream obfuscation.
#[derive(Clone, Debug)]
pub struct StreamCipher {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl StreamCipher {
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for k in 0..256 {
            s[k] = k as u8;
        }
        let mut j: u8 = 0;
        let key_len = if key.is_empty() { 1 } else { key.len() };
        for i in 0..256 {
            let key_byte = if key.is_empty() { 0 } else { key[i % key_len] };
            j = j.wrapping_add(s[i]).wrapping_add(key_byte);
            s.swap(i, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    pub fn apply_keystream(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k = self.s[self.s[self.i as usize].wrapping_add(self.s[self.j as usize]) as usize];
            *byte ^= k;
        }
    }
}

/// Derives a 16-byte key using 6000 recursive rounds of SHA-1 over seed, keyword, and IV.
pub fn derive_obfuscation_key(seed: &[u8; OBFUSCATE_SEED_LENGTH], keyword: &[u8], iv: &[u8]) -> [u8; OBFUSCATE_KEY_LENGTH] {
    let mut hasher = Sha1::new();
    hasher.update(seed);
    hasher.update(keyword);
    hasher.update(iv);
    let mut digest = hasher.finalize();

    for _ in 0..OBFUSCATE_HASH_ITERATIONS {
        let mut round_hasher = Sha1::new();
        round_hasher.update(&digest);
        digest = round_hasher.finalize();
    }

    let mut key = [0u8; OBFUSCATE_KEY_LENGTH];
    key.copy_from_slice(&digest[..OBFUSCATE_KEY_LENGTH]);
    key
}

/// Client or server side obfuscation session maintaining bidirectional stream ciphers.
#[derive(Debug)]
pub struct TacticalSessionObfuscator {

    keyword: Vec<u8>,
    seed: [u8; OBFUSCATE_SEED_LENGTH],
    client_to_server_cipher: StreamCipher,
    server_to_client_cipher: StreamCipher,
    padding_len: usize,
}

impl TacticalSessionObfuscator {
    /// Creates a new client obfuscator with a supplied or random 16-byte seed and padding.
    pub fn new_client(
        keyword: &[u8],
        seed: [u8; OBFUSCATE_SEED_LENGTH],
        padding_len: usize,
    ) -> Result<Self, TacticalSessionError> {
        if padding_len > OBFUSCATE_MAX_PADDING {
            return Err(TacticalSessionError::ExcessivePadding(padding_len));
        }

        let c2s_key = derive_obfuscation_key(&seed, keyword, OBFUSCATE_CLIENT_TO_SERVER_IV);
        let s2c_key = derive_obfuscation_key(&seed, keyword, OBFUSCATE_SERVER_TO_CLIENT_IV);

        let client_to_server_cipher = StreamCipher::new(&c2s_key);
        let server_to_client_cipher = StreamCipher::new(&s2c_key);

        Ok(Self {
            keyword: keyword.to_vec(),
            seed,
            client_to_server_cipher,
            server_to_client_cipher,
            padding_len,
        })
    }

    /// Emits the preamble bytes sent by the client:
    /// `[16-byte plaintext seed] || encrypt_c2s([0x0BF5CA7E (4B)] || [padding_len (4B)] || [padding bytes])`
    pub fn generate_client_preamble(&mut self, padding_bytes: &[u8]) -> Result<Vec<u8>, TacticalSessionError> {
        if padding_bytes.len() != self.padding_len {
            return Err(TacticalSessionError::BufferTooShort);
        }

        let mut payload = Vec::with_capacity(8 + self.padding_len);
        payload.extend_from_slice(&OBFUSCATE_MAGIC_VALUE.to_be_bytes());
        payload.extend_from_slice(&(self.padding_len as u32).to_be_bytes());
        payload.extend_from_slice(padding_bytes);

        // Encrypt with client-to-server cipher
        self.client_to_server_cipher.apply_keystream(&mut payload);

        let mut preamble = Vec::with_capacity(OBFUSCATE_SEED_LENGTH + payload.len());
        preamble.extend_from_slice(&self.seed);
        preamble.extend_from_slice(&payload);

        Ok(preamble)
    }

    /// Server side: parses client preamble, validates magic, checks padding length, and initialises ciphers.
    pub fn new_server_from_preamble(
        keyword: &[u8],
        preamble: &[u8],
    ) -> Result<(Self, Vec<u8>), TacticalSessionError> {
        if preamble.len() < PREAMBLE_HEADER_LENGTH {
            return Err(TacticalSessionError::BufferTooShort);
        }

        let mut seed = [0u8; OBFUSCATE_SEED_LENGTH];
        seed.copy_from_slice(&preamble[..OBFUSCATE_SEED_LENGTH]);

        let c2s_key = derive_obfuscation_key(&seed, keyword, OBFUSCATE_CLIENT_TO_SERVER_IV);
        let s2c_key = derive_obfuscation_key(&seed, keyword, OBFUSCATE_SERVER_TO_CLIENT_IV);

        let mut client_to_server_cipher = StreamCipher::new(&c2s_key);
        let server_to_client_cipher = StreamCipher::new(&s2c_key);

        let mut encrypted_hdr = preamble[OBFUSCATE_SEED_LENGTH..PREAMBLE_HEADER_LENGTH].to_vec();
        client_to_server_cipher.apply_keystream(&mut encrypted_hdr);

        let magic = u32::from_be_bytes([
            encrypted_hdr[0],
            encrypted_hdr[1],
            encrypted_hdr[2],
            encrypted_hdr[3],
        ]);

        if magic != OBFUSCATE_MAGIC_VALUE {
            return Err(TacticalSessionError::InvalidMagic(magic));
        }

        let padding_len = u32::from_be_bytes([
            encrypted_hdr[4],
            encrypted_hdr[5],
            encrypted_hdr[6],
            encrypted_hdr[7],
        ]) as usize;

        if padding_len > OBFUSCATE_MAX_PADDING {
            return Err(TacticalSessionError::ExcessivePadding(padding_len));
        }

        let total_required = PREAMBLE_HEADER_LENGTH + padding_len;
        if preamble.len() < total_required {
            return Err(TacticalSessionError::BufferTooShort);
        }

        let mut padding = preamble[PREAMBLE_HEADER_LENGTH..total_required].to_vec();
        client_to_server_cipher.apply_keystream(&mut padding);

        let session = Self {
            keyword: keyword.to_vec(),
            seed,
            client_to_server_cipher,
            server_to_client_cipher,
            padding_len,
        };

        Ok((session, padding))
    }

    /// Obfuscates or deobfuscates client-to-server payload in place.
    pub fn obfuscate_client_to_server(&mut self, data: &mut [u8]) {
        self.client_to_server_cipher.apply_keystream(data);
    }

    /// Obfuscates or deobfuscates server-to-client payload in place.
    pub fn obfuscate_server_to_client(&mut self, data: &mut [u8]) {
        self.server_to_client_cipher.apply_keystream(data);
    }

    pub fn seed(&self) -> &[u8; OBFUSCATE_SEED_LENGTH] {
        &self.seed
    }

    pub fn padding_len(&self) -> usize {
        self.padding_len
    }
}

/// Dynamic tactical configuration profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TacticsProfile {
    pub ttl: Duration,
    pub parameters: HashMap<String, String>,
    pub tag: String,
}

impl TacticsProfile {
    pub fn new(ttl: Duration, parameters: HashMap<String, String>) -> Self {
        let tag = Self::compute_tag(&parameters);
        Self { ttl, parameters, tag }
    }

    pub fn compute_tag(parameters: &HashMap<String, String>) -> String {
        let mut keys: Vec<&String> = parameters.keys().collect();
        keys.sort();
        let mut h = Sha1::new();
        for k in keys {
            h.update(k.as_bytes());
            h.update(b"=");
            h.update(parameters.get(k).unwrap().as_bytes());
            h.update(b";");
        }
        let digest = h.finalize();
        let mut hex_str = String::with_capacity(40);
        for b in digest {
            hex_str.push_str(&format!("{:02x}", b));
        }
        hex_str
    }
}

/// Filter matching client network characteristics.
#[derive(Debug, Clone)]
pub struct TacticsFilter {
    pub regions: Vec<String>,
    pub asns: Vec<u32>,
    pub max_latency_ms: Option<u64>,
    pub profile: TacticsProfile,
}

impl TacticsFilter {
    pub fn matches(&self, region: &str, asn: u32, latency_ms: u64) -> bool {
        if !self.regions.is_empty() && !self.regions.iter().any(|r| r.eq_ignore_ascii_case(region)) {
            return false;
        }
        if !self.asns.is_empty() && !self.asns.contains(&asn) {
            return false;
        }
        if let Some(max_lat) = self.max_latency_ms {
            if latency_ms > max_lat {
                return false;
            }
        }
        true
    }
}

/// Dynamic tactics engine resolving optimal tactical profile for given network attributes.
pub struct TacticsEngine {
    default_profile: TacticsProfile,
    filters: Vec<TacticsFilter>,
    cached_profile: Option<(TacticsProfile, Instant)>,
}

impl TacticsEngine {
    pub fn new(default_profile: TacticsProfile) -> Self {
        Self {
            default_profile,
            filters: Vec::new(),
            cached_profile: None,
        }
    }

    pub fn add_filter(&mut self, filter: TacticsFilter) {
        self.filters.push(filter);
    }

    pub fn resolve_profile(
        &mut self,
        region: &str,
        asn: u32,
        latency_ms: u64,
        force_refresh: bool,
    ) -> TacticsProfile {
        if !force_refresh {
            if let Some((ref cached, fetched_at)) = self.cached_profile {
                if fetched_at.elapsed() < cached.ttl {
                    return cached.clone();
                }
            }
        }

        let mut merged_params = self.default_profile.parameters.clone();
        let mut applied_ttl = self.default_profile.ttl;

        for filter in &self.filters {
            if filter.matches(region, asn, latency_ms) {
                for (k, v) in &filter.profile.parameters {
                    merged_params.insert(k.clone(), v.clone());
                }
                applied_ttl = filter.profile.ttl;
            }
        }

        let resolved = TacticsProfile::new(applied_ttl, merged_params);
        self.cached_profile = Some((resolved.clone(), Instant::now()));
        resolved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_obfuscation_key_determinism() {
        let seed = [0x42u8; 16];
        let keyword = b"luminet_secret_keyword";
        let k1 = derive_obfuscation_key(&seed, keyword, OBFUSCATE_CLIENT_TO_SERVER_IV);
        let k2 = derive_obfuscation_key(&seed, keyword, OBFUSCATE_CLIENT_TO_SERVER_IV);
        assert_eq!(k1, k2);
        assert_ne!(k1, [0u8; 16]);

        let k3 = derive_obfuscation_key(&seed, keyword, OBFUSCATE_SERVER_TO_CLIENT_IV);
        assert_ne!(k1, k3);
    }

    #[test]
    fn test_stream_cipher_xor_property() {
        let key = b"session_stream_cipher_key";
        let mut enc = StreamCipher::new(key);
        let mut dec = StreamCipher::new(key);

        let plaintext = b"Hello, encrypted tactical tunnel payload!";
        let mut buffer = plaintext.to_vec();

        enc.apply_keystream(&mut buffer);
        assert_ne!(&buffer, plaintext);

        dec.apply_keystream(&mut buffer);
        assert_eq!(&buffer, plaintext);
    }

    #[test]
    fn test_preamble_handshake_roundtrip() {
        let keyword = b"tactical_tunnel_master_key";
        let seed = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00];
        let padding_bytes = vec![0xEE; 64];

        let mut client = TacticalSessionObfuscator::new_client(keyword, seed, 64).expect("client init");
        let preamble = client.generate_client_preamble(&padding_bytes).expect("preamble generation");

        assert_eq!(preamble.len(), PREAMBLE_HEADER_LENGTH + 64);

        let (mut server, recovered_padding) =
            TacticalSessionObfuscator::new_server_from_preamble(keyword, &preamble).expect("server init");

        assert_eq!(recovered_padding, padding_bytes);
        assert_eq!(server.seed(), &seed);
        assert_eq!(server.padding_len(), 64);

        // Test stream transmission from client to server
        let msg = b"GET /tactical-stream HTTP/1.1\r\nHost: target\r\n\r\n";
        let mut payload = msg.to_vec();

        client.obfuscate_client_to_server(&mut payload);
        assert_ne!(&payload, msg);

        server.obfuscate_client_to_server(&mut payload);
        assert_eq!(&payload, msg);

        // Test response transmission from server to client
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nREADY";
        let mut resp_payload = response.to_vec();

        server.obfuscate_server_to_client(&mut resp_payload);
        assert_ne!(&resp_payload, response);

        client.obfuscate_server_to_client(&mut resp_payload);
        assert_eq!(&resp_payload, response);
    }

    #[test]
    fn test_preamble_tampered_magic_fails() {
        let keyword = b"tactical_key";
        let seed = [0x01; 16];
        let mut client = TacticalSessionObfuscator::new_client(keyword, seed, 16).unwrap();
        let mut preamble = client.generate_client_preamble(&vec![0xAA; 16]).unwrap();

        // Corrupt preamble ciphertext where magic resides
        preamble[16] ^= 0xFF;

        let res = TacticalSessionObfuscator::new_server_from_preamble(keyword, &preamble);
        match res {
            Err(TacticalSessionError::InvalidMagic(_)) => {}
            Ok(_) => panic!("expected error, got Ok"),
            Err(other) => panic!("expected InvalidMagic, got {:?}", other),
        }
    }

    #[test]
    fn test_tactics_engine_resolution_and_filter() {
        let mut default_params = HashMap::new();
        default_params.insert("timeout_ms".to_string(), "5000".to_string());
        default_params.insert("pool_size".to_string(), "2".to_string());

        let default_profile = TacticsProfile::new(Duration::from_secs(3600), default_params);
        let mut engine = TacticsEngine::new(default_profile);

        let mut high_latency_params = HashMap::new();
        high_latency_params.insert("timeout_ms".to_string(), "15000".to_string());
        high_latency_params.insert("pool_size".to_string(), "8".to_string());
        high_latency_params.insert("protocol_whitelist".to_string(), "FRONTED_HTTP,SSH_OBFUSCATED".to_string());

        let filter = TacticsFilter {
            regions: vec!["IR".to_string(), "RU".to_string()],
            asns: vec![12345],
            max_latency_ms: None,
            profile: TacticsProfile::new(Duration::from_secs(1800), high_latency_params),
        };
        engine.add_filter(filter);

        // Non-matching query gets default
        let resolved_us = engine.resolve_profile("US", 99999, 50, true);
        assert_eq!(resolved_us.parameters.get("timeout_ms").unwrap(), "5000");
        assert_eq!(resolved_us.parameters.get("pool_size").unwrap(), "2");
        assert!(!resolved_us.parameters.contains_key("protocol_whitelist"));

        // Matching query gets overridden
        let resolved_ir = engine.resolve_profile("IR", 12345, 250, true);
        assert_eq!(resolved_ir.parameters.get("timeout_ms").unwrap(), "15000");
        assert_eq!(resolved_ir.parameters.get("pool_size").unwrap(), "8");
        assert_eq!(resolved_ir.parameters.get("protocol_whitelist").unwrap(), "FRONTED_HTTP,SSH_OBFUSCATED");
        assert_ne!(resolved_us.tag, resolved_ir.tag);
    }
}
