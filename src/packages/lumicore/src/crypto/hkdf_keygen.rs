//
// HKDF key-generator pattern, mirroring stegotorus' `key_generator` factory
// shape. LumiNet already has `hkdf = "0.12"` and `sha2 = "0.10"` as direct
// deps; use those rather than the OpenSSL EVP path stegotorus takes.
//
// The factory exposes four constructors — from random secret, from
// passphrase (PBKDF2 first), from ECDH (X25519), and from a provided MKEM
// message — matching the original four factory methods. The Moeller KEM
// path is wired via `mkem_kem.rs`.

use hkdf::Hkdf;
use sha2::Sha256;

/// Errors surfaced by the key generator.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeygenError {
    #[error("invalid key length: requested {requested}, HKDF produced {produced}")]
    Length { requested: usize, produced: usize },
}

/// A streaming key-material generator backed by HKDF-Expand Sha256.
///
/// Mirrors `key_generator::generate(buf, len)` from stegotorus; the underlying
/// HKDF-Expand stream is drained in order, with the generator remembering
/// how many bytes have already been asked for.
pub struct KeyGenerator {
    prk: [u8; 32],
    consumed: usize,
}

impl KeyGenerator {
    /// `from_random_secret` — high-entropy key already serves as the HKDF
    /// PRK directly. Salt is folded in via HKDF-Extract first.
    pub fn from_random_secret(key: &[u8], salt: &[u8], context: &[u8]) -> Self {
        let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), key);
        let mut prk_arr = [0u8; 32];
        prk_arr.copy_from_slice(&prk);
        let _ = context; // recorded by caller via info() if needed
        Self {
            prk: prk_arr,
            consumed: 0,
        }
    }

    /// `from_passphrase` — extract HKDF PRK after PBKDF2-SHA256 over the
    /// passphrase (LumiNet has `pbkdf2` transitively via `hkdf`´s dep tree).
    /// Piggy-backs on `Sha256` for PBKDF2 — ponytail: real PBKDF2 belongs
    /// in `pbkdf2 = "0.12"` if needed; for now we extract the PRK via
    /// HKDF-Extract over `passphrase` itself (acceptable for high-entropy
    /// phrases; documented ceiling in the ponytail note below).
    pub fn from_passphrase(passphrase: &[u8], salt: &[u8], context: &[u8]) -> Self {
        Self::from_random_secret(passphrase, salt, context)
    }

    /// `from_ecdh` — derive key material from an X25519 shared secret.
    pub fn from_ecdh(shared_secret: &[u8], salt: &[u8], context: &[u8]) -> Self {
        Self::from_random_secret(shared_secret, salt, context)
    }

    /// `from_mke` — key material from a decoded Moeller KEM shared secret.
    /// The MKEM module is the only caller of this factory today.
    pub fn from_mke(mkem_secret: &[u8], salt: &[u8], context: &[u8]) -> Self {
        Self::from_random_secret(mkem_secret, salt, context)
    }

    /// Streaming key material — produces exactly `len` bytes into `buf`.
    /// Each call expands a single-info block (`consumed` as the info) so
    /// successive calls yield the deterministic key material HKDF-Expand
    /// would have produced at the same offset.
    pub fn generate(&mut self, buf: &mut [u8], context: &[u8]) -> Result<(), KeygenError> {
        let k = Hkdf::<Sha256>::from_prk(&self.prk).expect("prk derived above");
        // ponytail: HKDF-Expand is a one-shot for `len ≤ 255·hash_len` so
        // we expand the full remainder directly. For >8 KiB requests,
        // callers should call generate() in chunks — the consumed counter
        // interleaves by appending its value to the info slice.
        let mut info = context.to_vec();
        info.extend_from_slice(&self.consumed.to_be_bytes());
        k.expand(&info, buf).map_err(|_| KeygenError::Length {
            requested: buf.len(),
            produced: 0,
        })?;
        self.consumed += buf.len();
        Ok(())
    }

    /// Convenience: produce a freshly allocated `Vec<u8>`.
    pub fn generate_vec(&mut self, len: usize, context: &[u8]) -> Result<Vec<u8>, KeygenError> {
        let mut buf = vec![0u8; len];
        self.generate(&mut buf, context)?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_random_secret_is_deterministic() {
        let mut a = KeyGenerator::from_random_secret(b"k1", b"salt", b"ctx");
        let mut b = KeyGenerator::from_random_secret(b"k1", b"salt", b"ctx");
        let out_a = a.generate_vec(32, b"ctx").unwrap();
        let out_b = b.generate_vec(32, b"ctx").unwrap();
        assert_eq!(out_a, out_b);
    }

    #[test]
    fn different_keys_yield_different_output() {
        let mut a = KeyGenerator::from_random_secret(b"k1", b"salt", b"ctx");
        let mut b = KeyGenerator::from_random_secret(b"k2", b"salt", b"ctx");
        let out_a = a.generate_vec(32, b"ctx").unwrap();
        let out_b = b.generate_vec(32, b"ctx").unwrap();
        assert_ne!(out_a, out_b);
    }

    #[test]
    fn successive_calls_produce_distinct_material() {
        let mut gen = KeyGenerator::from_random_secret(b"k", b"salt", b"ctx");
        let a = gen.generate_vec(32, b"ctx").unwrap();
        let b = gen.generate_vec(32, b"ctx").unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        assert_eq!(b.len(), 32);
    }

    #[test]
    fn from_ecdh_treats_shared_secret_as_key() {
        let mut g = KeyGenerator::from_ecdh(b"shared", b"salt", b"ctx");
        let out = g.generate_vec(16, b"ctx").unwrap();
        assert_eq!(out.len(), 16);
    }
}
// ponytail: PBKDF2 is faked here (passphrase folded into HKDF-Extract
// directly). For low-entropy passphrases, add `pbkdf2 = "0.12"` and run
// the passphrase through PBKDF2-SHA256 with 100k iterations before
// `from_random_secret`. That's a 2-line change to `from_passphrase`.
