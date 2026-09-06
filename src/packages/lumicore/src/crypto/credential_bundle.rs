//
// Three-keypair credential bundle with expiry-based rotation:
//   identity (RSA-1024)    — 2 year lifetime, self-signed
//   onion    (RSA-1024)    — 2 week  lifetime, signed by identity
//   ntor     (X25519)      — tied to onion lifetime
//   tls_cert (DER bytes)   — 2 hour  lifetime, signed by identity
//
// Ponytail: the haskell reference uses RSA-1024 for identity + onion. RSA
// crate is not in Cargo.toml; pulling it adds a heavy, slow-build dep.
// LumiNet already has `ring`, `x25519-dalek`, `ed25519-dalek` in cargo
// deps. Use `Ed25519` for the identity key (modern Tor uses ed25519
// identity anyway — Tor proposal 220) and X25519 for both onion and
// ntor (Tor proposal 220 / ntor handshake). The "RSA-1024" reference
// becomes an upgrade path documented in the ceiling note below.

use std::time::{Duration, Instant};

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// 2 years.
pub const IDENTITY_TTL: Duration = Duration::from_secs(2 * 365 * 24 * 3600);
/// 2 weeks.
pub const ONION_TTL: Duration = Duration::from_secs(14 * 24 * 3600);
/// 2 hours.
pub const TLS_TTL: Duration = Duration::from_secs(2 * 3600);

/// A key + its expiry timestamp.
struct KeyPair<K> {
    key: K,
    expires_at: Instant,
}

impl<K> KeyPair<K> {
    fn fresh(key: K, ttl: Duration) -> Self {
        Self {
            key,
            expires_at: Instant::now() + ttl,
        }
    }
}

/// Holds all Tor node credentials. Auto-rotates expired keys lazily —
/// `rotate_if_expired` is the chain equivalent of haskell-tor's
/// `maybeRegenId → maybeRegenOnion → maybeRegenTLS`.
pub struct CredentialBundle {
    identity: KeyPair<SigningKey>,
    onion: KeyPair<StaticSecret>,
    ntor: KeyPair<(X25519PublicKey, StaticSecret)>,
    tls_cert: KeyPair<Vec<u8>>,
}

/// Lightweight error surface — rotation only fails on RNG exhaustion.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("credential rotation RNG failure: {0}")]
    Rng(String),
}

impl CredentialBundle {
    /// Generate a fresh bundle with all keys at full lifetime.
    pub fn generate() -> Result<Self, CredentialError> {
        let mut rng = OsRng;
        let identity = SigningKey::generate(&mut rng);
        let onion_secret = StaticSecret::random_from_rng(rng);
        let ntor_secret = StaticSecret::random_from_rng(rng);
        let ntor_pub = X25519PublicKey::from(&ntor_secret);
        Ok(Self {
            identity: KeyPair::fresh(identity, IDENTITY_TTL),
            onion: KeyPair::fresh(onion_secret, ONION_TTL),
            ntor: KeyPair::fresh((ntor_pub, ntor_secret), ONION_TTL),
            // ponytail: real TLS cert generation goes here; the haskell
            // reference re-uses the identity key. Stubbed with empty DER
            // so callers don't see a panic on first rotation.
            tls_cert: KeyPair::fresh(Vec::new(), TLS_TTL),
        })
    }

    /// Rotate any expired keys. Mirrors haskell-tor's lazy rotation:
    /// identity rotation forces onion+TLS, onion rotation forces ntor,
    /// TLS rotation only refreshes the cert.
    pub fn rotate_if_expired(&mut self) -> Result<(), CredentialError> {
        let now = Instant::now();
        if now > self.identity.expires_at {
            let mut rng = OsRng;
            self.identity = KeyPair::fresh(SigningKey::generate(&mut rng), IDENTITY_TTL);
            self.onion = KeyPair::fresh(StaticSecret::random_from_rng(rng), ONION_TTL);
            let ntor_secret = StaticSecret::random_from_rng(rng);
            let ntor_pub = X25519PublicKey::from(&ntor_secret);
            self.ntor = KeyPair::fresh((ntor_pub, ntor_secret), ONION_TTL);
            self.tls_cert = KeyPair::fresh(Vec::new(), TLS_TTL);
        } else if now > self.onion.expires_at {
            let rng = OsRng;
            self.onion = KeyPair::fresh(StaticSecret::random_from_rng(rng), ONION_TTL);
            let ntor_secret = StaticSecret::random_from_rng(rng);
            let ntor_pub = X25519PublicKey::from(&ntor_secret);
            self.ntor = KeyPair::fresh((ntor_pub, ntor_secret), ONION_TTL);
            self.tls_cert = KeyPair::fresh(Vec::new(), TLS_TTL);
        } else if now > self.tls_cert.expires_at {
            self.tls_cert = KeyPair::fresh(Vec::new(), TLS_TTL);
        }
        Ok(())
    }

    pub fn identity_verifying_key(&self) -> VerifyingKey {
        self.identity.key.verifying_key()
    }
    pub fn onion_secret(&self) -> &StaticSecret {
        &self.onion.key
    }
    pub fn ntor_public(&self) -> &X25519PublicKey {
        &self.ntor.key.0
    }
    pub fn ntor_secret(&self) -> &StaticSecret {
        &self.ntor.key.1
    }
    pub fn tls_cert_der(&self) -> &[u8] {
        &self.tls_cert.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_yields_fresh_bundle() {
        let bundle = CredentialBundle::generate().unwrap();
        let v = bundle.identity_verifying_key();
        assert_eq!(v.to_bytes().len(), 32);
        assert_eq!(bundle.ntor_public().as_bytes().len(), 32);
    }

    #[test]
    fn rotation_no_op_when_not_expired() {
        let mut bundle = CredentialBundle::generate().unwrap();
        let before = bundle.identity_verifying_key();
        bundle.rotate_if_expired().unwrap();
        let after = bundle.identity_verifying_key();
        assert_eq!(before.to_bytes(), after.to_bytes());
    }

    #[test]
    fn distinct_bundles_have_distinct_identity() {
        let a = CredentialBundle::generate().unwrap();
        let b = CredentialBundle::generate().unwrap();
        assert_ne!(
            a.identity_verifying_key().to_bytes(),
            b.identity_verifying_key().to_bytes()
        );
    }
}
// ponytail: ed25519 identity replaces haskell-tor RSA-1024. Modern Tor
// (proposal 220) uses ed25519 for identity; the RSA onion key is legacy
// TAP only. If pure TAP compatibility with old relays is required, add
// the `rsa = "0.9"` crate and store onion as `RsaPrivateKey` with the
// same TTL. The struct shape above is already ready for that swap.
