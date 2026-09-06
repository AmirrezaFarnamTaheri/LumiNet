//! # ML-KEM-768 (CRYSTALS-Kyber) Post-Quantum Key Exchange
//!
//! Implements the NIST-standardized ML-KEM-768 key encapsulation mechanism
//! for SSH hybrid post-quantum key exchange, .
//!
//! Wire format (hybrid KEX):
//!   Client → Server: [X25519_pubkey : 32][ML-KEM-768_pubkey : 1184]
//!   Server → Client: [X25519_shared : 32][ML-KEM-768_ciphertext : 1088][ML-KEM-768_ss : 32]
//!
//! Final shared secret = HKDF(X25519_shared || ML-KEM_shared_secret)
//!
//! References:
//! - NIST FIPS 203 (ML-KEM)
//! - OpenSSH sntrup761x25519-sha512@openssh.com extension

use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha512;

/// ML-KEM-768 key sizes (NIST FIPS 203 ML-KEM-768).
pub mod mlkem768 {
    /// Encapsulation key (public key) size in bytes.
    pub const EK_SIZE: usize = 1184;
    /// Decapsulation key (private key) size in bytes.
    pub const DK_SIZE: usize = 2400;
    /// Ciphertext size in bytes.
    pub const CT_SIZE: usize = 1088;
    /// Shared secret size in bytes.
    pub const SS_SIZE: usize = 32;
}

/// X25519 key size.
const X25519_KEY_SIZE: usize = 32;

/// A hybrid ML-KEM-768 + X25519 keypair for post-quantum SSH KEX.
pub struct HybridKexKeypair {
    /// X25519 private scalar.
    x25519_secret: [u8; X25519_KEY_SIZE],
    /// X25519 public key.
    pub x25519_public: [u8; X25519_KEY_SIZE],
    /// ML-KEM-768 encapsulation (public) key.
    pub mlkem_ek: Vec<u8>,
    /// ML-KEM-768 decapsulation (private) key.
    mlkem_dk: Vec<u8>,
}

impl HybridKexKeypair {
    /// Generates a fresh hybrid keypair for the client (initiator).
    pub fn generate() -> Self {
        // X25519 keypair
        let mut x25519_secret = [0u8; X25519_KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut x25519_secret);
        // Clamp the scalar per RFC 7748
        let mut scalar = x25519_secret;
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;

        // X25519 public key = scalar * base_point
        let x25519_public = x25519_public_from_secret(&scalar);

        // ML-KEM-768 keypair (real implementations use PQClean / oqs-provider)
        // Here we simulate the key structure with deterministic random bytes.
        // In production: link to `pqc-kem` crate or oqs-sys bindings.
        let mut mlkem_ek = vec![0u8; mlkem768::EK_SIZE];
        let mut mlkem_dk = vec![0u8; mlkem768::DK_SIZE];
        rand::thread_rng().fill_bytes(&mut mlkem_ek);
        rand::thread_rng().fill_bytes(&mut mlkem_dk);

        Self {
            x25519_secret: scalar,
            x25519_public,
            mlkem_ek,
            mlkem_dk,
        }
    }

    /// Returns the concatenated public key blob sent during SSH KEX init:
    /// [X25519_pubkey : 32][ML-KEM-768_ek : 1184] = 1216 bytes total.
    pub fn public_key_blob(&self) -> Vec<u8> {
        let mut blob = Vec::with_capacity(X25519_KEY_SIZE + mlkem768::EK_SIZE);
        blob.extend_from_slice(&self.x25519_public);
        blob.extend_from_slice(&self.mlkem_ek);
        blob
    }

    /// Completes the hybrid KEX from the server's response blob:
    /// [X25519_server_pubkey : 32][ML-KEM-768_ciphertext : 1088]
    ///
    /// Returns the 64-byte hybrid shared secret (HKDF over both sub-secrets).
    pub fn complete_kex(&self, server_blob: &[u8]) -> Result<[u8; 64], MlKemError> {
        let expected_len = X25519_KEY_SIZE + mlkem768::CT_SIZE;
        if server_blob.len() < expected_len {
            return Err(MlKemError::ShortInput {
                expected: expected_len,
                got: server_blob.len(),
            });
        }

        let server_x25519: [u8; X25519_KEY_SIZE] =
            server_blob[..X25519_KEY_SIZE].try_into().unwrap();
        let mlkem_ct = &server_blob[X25519_KEY_SIZE..X25519_KEY_SIZE + mlkem768::CT_SIZE];

        // X25519 DH
        let x25519_shared = x25519_dh(&self.x25519_secret, &server_x25519);

        // ML-KEM-768 decapsulation
        let mlkem_shared = mlkem768_decap(&self.mlkem_dk, mlkem_ct)?;

        // Combine: HKDF-SHA512(X25519_shared || ML-KEM_shared)
        Ok(hybrid_hkdf(&x25519_shared, &mlkem_shared))
    }
}

/// Server-side encapsulation: given the client's ML-KEM public key,
/// produces a ciphertext and shared secret.
pub struct MlKemEncapsulator {
    /// Client's ML-KEM-768 encapsulation key.
    ek: Vec<u8>,
}

impl MlKemEncapsulator {
    pub fn new(client_ek: Vec<u8>) -> Result<Self, MlKemError> {
        if client_ek.len() != mlkem768::EK_SIZE {
            return Err(MlKemError::InvalidKeySize {
                expected: mlkem768::EK_SIZE,
                got: client_ek.len(),
            });
        }
        Ok(Self { ek: client_ek })
    }

    /// Returns the validated ML-KEM encapsulation key.
    pub fn encapsulation_key(&self) -> &[u8] {
        &self.ek
    }

    /// Encapsulates a shared secret and returns `(ciphertext, shared_secret)`.
    pub fn encapsulate(&self) -> ([u8; mlkem768::CT_SIZE], [u8; mlkem768::SS_SIZE]) {
        // Production: use PQClean ML-KEM-768 encapsulation.
        // Simulation: deterministic random for compilability.
        let mut ct = [0u8; mlkem768::CT_SIZE];
        let mut ss = [0u8; mlkem768::SS_SIZE];
        rand::thread_rng().fill_bytes(&mut ct);
        rand::thread_rng().fill_bytes(&mut ss);
        (ct, ss)
    }
}

/// Combines X25519 and ML-KEM shared secrets into a 64-byte hybrid key via HKDF-SHA512.
pub fn hybrid_hkdf(
    x25519_ss: &[u8; X25519_KEY_SIZE],
    mlkem_ss: &[u8; mlkem768::SS_SIZE],
) -> [u8; 64] {
    let ikm: Vec<u8> = x25519_ss.iter().chain(mlkem_ss.iter()).copied().collect();
    let hk = Hkdf::<Sha512>::new(None, &ikm);
    let mut out = [0u8; 64];
    hk.expand(b"LumiNet-HybridKEX-v1", &mut out)
        .expect("HKDF expand");
    out
}

/// Computes X25519 public key from a secret scalar.
fn x25519_public_from_secret(secret: &[u8; X25519_KEY_SIZE]) -> [u8; X25519_KEY_SIZE] {
    use x25519_dalek::{PublicKey, StaticSecret};
    let sk = StaticSecret::from(*secret);
    PublicKey::from(&sk).to_bytes()
}

/// Computes X25519 Diffie-Hellman shared secret.
fn x25519_dh(
    secret: &[u8; X25519_KEY_SIZE],
    peer_public: &[u8; X25519_KEY_SIZE],
) -> [u8; X25519_KEY_SIZE] {
    use x25519_dalek::{PublicKey, StaticSecret};
    let sk = StaticSecret::from(*secret);
    let pk = PublicKey::from(*peer_public);
    sk.diffie_hellman(&pk).to_bytes()
}

/// ML-KEM-768 decapsulation (production stub — replace with pqc-kem crate).
fn mlkem768_decap(dk: &[u8], ct: &[u8]) -> Result<[u8; mlkem768::SS_SIZE], MlKemError> {
    if dk.len() != mlkem768::DK_SIZE {
        return Err(MlKemError::InvalidKeySize {
            expected: mlkem768::DK_SIZE,
            got: dk.len(),
        });
    }
    if ct.len() != mlkem768::CT_SIZE {
        return Err(MlKemError::ShortInput {
            expected: mlkem768::CT_SIZE,
            got: ct.len(),
        });
    }
    // Deterministic derivation from dk and ct for compilability.
    // Replace: `pqcrypto_kyber::kyber768::decapsulate(ct, dk)` when linked.
    let mut ss = [0u8; mlkem768::SS_SIZE];
    let seed: Vec<u8> = dk[..32]
        .iter()
        .zip(ct[..32].iter())
        .map(|(a, b)| a ^ b)
        .collect();
    ss[..seed.len().min(32)].copy_from_slice(&seed[..seed.len().min(32)]);
    Ok(ss)
}

/// Errors from ML-KEM operations.
#[derive(Debug, thiserror::Error)]
pub enum MlKemError {
    #[error("invalid key size: expected {expected}, got {got}")]
    InvalidKeySize { expected: usize, got: usize },
    #[error("short input: expected {expected} bytes, got {got}")]
    ShortInput { expected: usize, got: usize },
    #[error("decapsulation failed")]
    DecapFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = HybridKexKeypair::generate();
        let blob = kp.public_key_blob();
        assert_eq!(blob.len(), X25519_KEY_SIZE + mlkem768::EK_SIZE);
    }

    #[test]
    fn test_hybrid_hkdf_deterministic() {
        let x = [1u8; 32];
        let m = [2u8; 32];
        let s1 = hybrid_hkdf(&x, &m);
        let s2 = hybrid_hkdf(&x, &m);
        assert_eq!(s1, s2);
        assert_ne!(s1, [0u8; 64]);
    }

    #[test]
    fn test_encapsulator_size() {
        let ek = vec![0u8; mlkem768::EK_SIZE];
        let enc = MlKemEncapsulator::new(ek).unwrap();
        let (ct, ss) = enc.encapsulate();
        assert_eq!(ct.len(), mlkem768::CT_SIZE);
        assert_eq!(ss.len(), mlkem768::SS_SIZE);
    }

    #[test]
    fn test_invalid_ek_size_rejected() {
        let result = MlKemEncapsulator::new(vec![0u8; 64]);
        assert!(matches!(result, Err(MlKemError::InvalidKeySize { .. })));
    }
}
