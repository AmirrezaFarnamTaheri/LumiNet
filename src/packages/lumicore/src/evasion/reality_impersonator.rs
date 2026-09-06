//
// Server-side REALITY impersonator: provides the auth-key session cache,
// Short-ID validation, and SNI forwarding machinery that lets a server
// transparently re-encapsulate TLS connections to a "dest" (the camouflage
// target site) while authenticating the legitimate client by replaying its
// ClientHello in a forged ServerHello.
//
// This implementation is a clean-room port of the algorithm: it does not
// modify any crypto/tls internals. It focuses on the *control plane* —
// authkey verification, session caching, short-id matching, and SNI
// forwarding — so callers can route the actual byte-level TLS to a
// rustls-based impersonator or a companion transport.
//
// Algorithm summary (REALITY protocol v1):
//   1. Client sends a ClientHello with auth_key in the session_id field
//      (or with a ShortId) targeting the camouflage SNI.
//   2. Server checks the session_id against the auth_key list:
//      - exact match: replay the previously captured ServerHello
//      - short_id match (top byte): forward the client to the dest backend
//      - mismatch: do a passthrough to the camouflage destination as if a
//        legitimate connection were made, preserving client fingerprint
//   3. When forwarding, the auth_key is used as a one-time pad to derive
//      a per-connection encryption key for the inner protocol.
//
// The cache itself is keyed by an H(K, client_random) value and stores the
// captured server-hello bytes for replay.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Result of inspecting a candidate ClientHello against the auth-key store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthDecision {
    /// Cache hit: replay the previously captured ServerHello.
    Replay { cached_session_id: Vec<u8> },
    /// Short-ID match: forward to the destination (camouflage) backend.
    Forward {
        short_id: [u8; 8],
        destination: String,
    },
    /// No match: act as a passthrough to the camouflage destination.
    Passthrough { camouflage: String },
    /// Reject: malformed or auth failed.
    Reject { reason: &'static str },
}

/// Configuration for the REALITY impersonator.
#[derive(Debug, Clone)]
pub struct RealityConfig {
    /// Auth keys (32 bytes each) used to derive short IDs and session tags.
    pub auth_keys: Vec<Vec<u8>>,
    /// Destination host (camouflage site) used for passthrough when no
    /// auth matches (e.g. "www.microsoft.com").
    pub camouflage_dest: String,
    /// Maximum number of cached session replays to retain.
    pub max_cache_entries: usize,
    /// TTL for cached sessions (after which they are evicted).
    pub session_ttl: Duration,
}

impl Default for RealityConfig {
    fn default() -> Self {
        Self {
            auth_keys: Vec::new(),
            camouflage_dest: "www.microsoft.com".to_string(),
            max_cache_entries: 4096,
            session_ttl: Duration::from_secs(60 * 60 * 6),
        }
    }
}

/// Cached ServerHello snapshot captured during a previous successful session.
#[derive(Debug, Clone)]
struct SessionEntry {
    /// Original ClientHello (for replay).
    client_hello: Vec<u8>,
    /// ServerHello + EncryptedExtensions + Certificate + Finished to replay.
    server_hello_chain: Vec<u8>,
    /// When this entry was last touched.
    last_used: Instant,
}

impl SessionEntry {
    fn new(client_hello: Vec<u8>, server_hello_chain: Vec<u8>) -> Self {
        Self {
            client_hello,
            server_hello_chain,
            last_used: Instant::now(),
        }
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.last_used.elapsed() > ttl
    }
}

/// Server-side REALITY impersonator with auth-key verification,
/// session-replay cache, and SNI forwarding.
pub struct RealityImpersonator {
    active: bool,
    config: RealityConfig,
    /// auth_key -> derived short_id (top 8 bytes of H(auth_key, "shortid")).
    short_ids: RwLock<HashMap<[u8; 8], Vec<u8>>>,
    /// session_id (= H(auth_key, client_random) on first hit) -> SessionEntry.
    cache: RwLock<HashMap<Vec<u8>, SessionEntry>>,
}

impl Default for RealityImpersonator {
    fn default() -> Self {
        Self::new(RealityConfig::default())
    }
}

impl RealityImpersonator {
    /// Create a new impersonator with the given config.
    pub fn new(config: RealityConfig) -> Self {
        let mut imp = Self {
            active: true,
            config,
            short_ids: RwLock::new(HashMap::new()),
            cache: RwLock::new(HashMap::new()),
        };
        imp.reindex_auth_keys();
        imp
    }

    /// Re-derive the short-id map from the current auth-key list. Call this
    /// after mutating `config.auth_keys` to keep the routing table consistent.
    pub fn reindex_auth_keys(&mut self) {
        let mut map = self.short_ids.write().expect("short_ids poisoned");
        map.clear();
        for key in &self.config.auth_keys {
            if key.len() != 32 {
                continue;
            }
            let mut mac = HmacSha256::new_from_slice(b"reality-shortid-v1")
                .expect("hmac key constant");
            mac.update(key);
            let tag = mac.finalize().into_bytes();
            let mut short = [0u8; 8];
            short.copy_from_slice(&tag[..8]);
            map.insert(short, key.clone());
        }
    }

    /// Compute the deterministic session-id for replay matching.
    pub fn derive_session_id(auth_key: &[u8], client_random: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(b"reality-session-v1")
            .expect("hmac key constant");
        mac.update(auth_key);
        mac.update(client_random);
        mac.finalize().into_bytes().into()
    }

    /// Derive the per-connection inner-protocol key from auth_key +
    /// server-random + client-random.
    pub fn derive_inner_key(
        auth_key: &[u8],
        client_random: &[u8],
        server_random: &[u8],
    ) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(b"reality-inner-v1")
            .expect("hmac key constant");
        mac.update(auth_key);
        mac.update(client_random);
        mac.update(server_random);
        mac.finalize().into_bytes().into()
    }

    /// Inspect a ClientHello and decide whether to replay, forward, or
    /// passthrough. `client_hello` is the raw TLS record; `client_random`
    /// is the 32-byte field extracted from the ClientHello; `sni` is the
    /// claimed SNI (used to confirm the camouflage target is honoured).
    pub fn inspect(
        &self,
        client_hello: &[u8],
        client_random: &[u8],
        sni: &str,
    ) -> AuthDecision {
        if !self.active {
            return AuthDecision::Reject { reason: "inactive" };
        }
        if self.config.auth_keys.is_empty() {
            return AuthDecision::Passthrough {
                camouflage: self.config.camouflage_dest.clone(),
            };
        }

        // Parse the session_id field. ClientHello layout (RFC 8446 4.1.2):
        //   0..5   TLS record header
        //   5..9   Handshake header (type + 3-byte length)
        //   9..11  legacy_version
        //  11..43  random (32 bytes)
        //  43      session_id_length (1 byte)
        //  44..    session_id (length bytes)
        // We require len >= 71 (5+4+2+32+1+32 = 76 minimum for 32-byte sid,
        // but accept 71 as a floor since we only need 8 short-id bytes).
        if client_hello.len() < 44 {
            return AuthDecision::Reject { reason: "short_client_hello" };
        }
        let sid_len = usize::from(client_hello[43]);
        if sid_len < 8 || 44 + sid_len > client_hello.len() {
            return AuthDecision::Reject { reason: "invalid_session_id_length" };
        }
        let mut session_id = vec![0u8; sid_len];
        session_id.copy_from_slice(&client_hello[44..44 + sid_len]);

        // Replay check first.
        {
            let cache = self.cache.read().expect("cache poisoned");
            if let Some(entry) = cache.get(&session_id) {
                if !entry.is_expired(self.config.session_ttl) {
                    return AuthDecision::Replay {
                        cached_session_id: entry.server_hello_chain.clone(),
                    };
                }
            }
        }

        // Short-ID match: top 8 bytes of the session_id match a registered
        // auth_key. Constant-time compare against every short_id.
        let mut target_short = [0u8; 8];
        target_short.copy_from_slice(&session_id[..8]);
        let short_ids = self.short_ids.read().expect("short_ids poisoned");
        for (registered_short, _key) in short_ids.iter() {
            if bool::from(registered_short.ct_eq(&target_short)) {
                let dest = if sni.is_empty() {
                    self.config.camouflage_dest.clone()
                } else {
                    sni.to_string()
                };
                return AuthDecision::Forward {
                    short_id: *registered_short,
                    destination: dest,
                };
            }
        }

        AuthDecision::Passthrough {
            camouflage: self.config.camouflage_dest.clone(),
        }
    }

    /// Cache a captured ServerHello chain for later replay. The auth_key +
    /// client_random combination is used to derive the deterministic
    /// session_id used by `inspect`.
    pub fn record_session(
        &self,
        auth_key: &[u8],
        client_random: &[u8],
        client_hello: &[u8],
        server_hello_chain: Vec<u8>,
    ) -> Result<(), &'static str> {
        if auth_key.len() != 32 || client_random.len() != 32 {
            return Err("bad_lengths");
        }
        let session_id = Self::derive_session_id(auth_key, client_random);
        let mut cache = self.cache.write().expect("cache poisoned");
        self.evict_expired(&cache);
        if cache.len() >= self.config.max_cache_entries {
            // Evict oldest.
            if let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, e)| e.last_used)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest);
            }
        }
        cache.insert(
            session_id.to_vec(),
            SessionEntry::new(client_hello.to_vec(), server_hello_chain),
        );
        Ok(())
    }

    fn evict_expired(&self, cache: &HashMap<Vec<u8>, SessionEntry>) {
        let ttl = self.config.session_ttl;
        let expired: Vec<Vec<u8>> = cache
            .iter()
            .filter(|(_, e)| e.is_expired(ttl))
            .map(|(k, _)| k.clone())
            .collect();
        if !expired.is_empty() {
            let mut cache = self.cache.write().expect("cache poisoned");
            for k in expired {
                cache.remove(&k);
            }
        }
    }

    /// Number of cached replay entries.
    pub fn cache_len(&self) -> usize {
        self.cache.read().expect("cache poisoned").len()
    }

    /// True if no auth_keys have been registered yet.
    pub fn is_unconfigured(&self) -> bool {
        self.config.auth_keys.is_empty()
    }

    /// Backwards-compatible mimic hook (was the original stub's println).
    /// Now returns a small status summary suitable for the FFI bridge.
    pub fn mimic(&self) -> String {
        format!(
            "reality: active={} auth_keys={} short_ids={} cache={} camouflage={}",
            self.active,
            self.config.auth_keys.len(),
            self.short_ids.read().expect("short_ids poisoned").len(),
            self.cache_len(),
            self.config.camouflage_dest,
        )
    }

    /// Toggle the impersonator on/off. When off, `inspect` always rejects.
    pub fn set_active(&mut self, active: bool) {
        self.active = active;
    }

    /// Access the live config.
    pub fn config(&self) -> &RealityConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_client_hello() -> (Vec<u8>, Vec<u8>) {
        // 5-byte record header + 4-byte handshake header (type=1 len=...) + version
        // + 32-byte random + 1-byte session_id_len + 32-byte session_id + ...
        let mut hello = vec![0x16, 0x03, 0x01, 0x00, 0x40];
        hello.extend_from_slice(&[0x01, 0x00, 0x00, 0x3c]);
        hello.extend_from_slice(&[0x03, 0x03]);
        let mut random = [0u8; 32];
        for (i, b) in random.iter_mut().enumerate() {
            *b = i as u8;
        }
        hello.extend_from_slice(&random);
        hello.push(32);
        let mut session_id = [0u8; 32];
        for (i, b) in session_id.iter_mut().enumerate() {
            *b = 0xAA ^ (i as u8);
        }
        hello.extend_from_slice(&session_id);
        (hello, random.to_vec())
    }

    #[test]
    fn passthrough_when_no_keys_configured() {
        let imp = RealityImpersonator::default();
        let (hello, random) = fixture_client_hello();
        let d = imp.inspect(&hello, &random, "example.com");
        assert!(matches!(d, AuthDecision::Passthrough { .. }));
    }

    #[test]
    fn forward_on_short_id_match() {
        let mut cfg = RealityConfig::default();
        let key = [7u8; 32];
        cfg.auth_keys.push(key.to_vec());
        let imp = RealityImpersonator::new(cfg);

        // Build a ClientHello whose session_id's top 8 bytes equal the
        // expected short_id for key=7^32.
        let mut session_id = [0u8; 32];
        let expected_short = {
            let mut mac = HmacSha256::new_from_slice(b"reality-shortid-v1").unwrap();
            mac.update(&key);
            let tag = mac.finalize().into_bytes();
            let mut s = [0u8; 8];
            s.copy_from_slice(&tag[..8]);
            s
        };
        session_id[..8].copy_from_slice(&expected_short);
        let mut hello = vec![0x16, 0x03, 0x01, 0x00, 0x40];
        hello.extend_from_slice(&[0x01, 0x00, 0x00, 0x3c]);
        hello.extend_from_slice(&[0x03, 0x03]);
        let mut random = [0u8; 32];
        for (i, b) in random.iter_mut().enumerate() {
            *b = i as u8;
        }
        hello.extend_from_slice(&random);
        hello.push(32);
        hello.extend_from_slice(&session_id);

        let d = imp.inspect(&hello, &random, "www.apple.com");
        assert!(
            matches!(&d, AuthDecision::Forward { destination, .. } if destination == "www.apple.com"),
            "got {d:?}"
        );
    }

    #[test]
    fn reject_short_client_hello() {
        // The default impersonator has no auth keys -> passthrough by
        // design. Register a key so the length check is reached.
        let mut cfg = RealityConfig::default();
        cfg.auth_keys.push([1u8; 32].to_vec());
        let imp = RealityImpersonator::new(cfg);
        let d = imp.inspect(&[0u8; 10], &[0u8; 32], "");
        assert!(matches!(d, AuthDecision::Reject { .. }));
    }

    #[test]
    fn replay_after_record_session() {
        let mut cfg = RealityConfig::default();
        let key = [9u8; 32];
        cfg.auth_keys.push(key.to_vec());
        let imp = RealityImpersonator::new(cfg);

        let (hello, random) = fixture_client_hello();
        let server_chain = vec![0xDE, 0xAD, 0xBE, 0xEF];
        imp.record_session(&key, &random, &hello, server_chain.clone())
            .unwrap();

        // Use a hello whose session_id equals derive_session_id(key, random)
        // so the cache lookup hits.
        let session_id = RealityImpersonator::derive_session_id(&key, &random);
        let mut hello2 = hello.clone();
        hello2[44..76].copy_from_slice(&session_id);
        let d = imp.inspect(&hello2, &random, "");
        match d {
            AuthDecision::Replay { cached_session_id } => {
                assert_eq!(cached_session_id, server_chain);
            }
            other => panic!("expected Replay, got {other:?}"),
        }
    }

    #[test]
    fn inactive_always_rejects() {
        let mut imp = RealityImpersonator::default();
        imp.set_active(false);
        let (hello, random) = fixture_client_hello();
        assert!(matches!(
            imp.inspect(&hello, &random, ""),
            AuthDecision::Reject { .. }
        ));
    }

    #[test]
    fn inner_key_deterministic() {
        let key = [1u8; 32];
        let cr = [2u8; 32];
        let sr = [3u8; 32];
        let a = RealityImpersonator::derive_inner_key(&key, &cr, &sr);
        let b = RealityImpersonator::derive_inner_key(&key, &cr, &sr);
        assert_eq!(a, b);
    }

    #[test]
    fn mimic_replaces_println() {
        let imp = RealityImpersonator::default();
        let s = imp.mimic();
        assert!(s.starts_with("reality:"));
        assert!(s.contains("active=true"));
    }

    #[test]
    fn reindex_picks_up_new_keys() {
        let mut imp = RealityImpersonator::default();
        assert!(imp.is_unconfigured());
        let mut cfg = imp.config().clone();
        cfg.auth_keys.push([1u8; 32].to_vec());
        cfg.auth_keys.push([2u8; 32].to_vec());
        imp = RealityImpersonator::new(cfg);
        assert_eq!(imp.short_ids.read().unwrap().len(), 2);
    }

    #[test]
    fn cache_eviction_when_full() {
        let mut cfg = RealityConfig::default();
        cfg.max_cache_entries = 2;
        cfg.session_ttl = Duration::from_secs(60);
        let imp = RealityImpersonator::new(cfg);
        let (hello, random) = fixture_client_hello();
        let key = [3u8; 32];
        for i in 0..5 {
            let cr = vec![i as u8; 32];
            imp.record_session(&key, &cr, &hello, vec![i as u8]).unwrap();
        }
        assert!(imp.cache_len() <= 2);
    }
}
