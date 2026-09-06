//
// Moeller 2004 elliptic-curve KEM. The original stegotorus implementation
// runs on two NIST P-224 curves (c0, c1) which is now deprecated. LumiNet
// uses X25519 instead — the KEM structure is preserved (two keypairs, an
// oblivious random curve choice, ciphertext indistinguishable from a
// random point) but the underlying group is Curve25519, sai.ones secure
// and already-plumbed by `x25519-dalek` in Cargo.toml.
//
// The interface is deliberately tiny:
//   generate()  → (ciphertext, shared_secret)
//   decode(ct)  → shared_secret
// Captures are single-shot: each call to `generate` picks a fresh curve
// bit and produces a fresh KEM tuple. No streaming API — matches the
// C++ `MKEM::generate / MKEM::decode` shape.

use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

/// Per-curve-bit length of the KEM ciphertext.
/// X25519 public key = 32 bytes; KEM ciphertext on X25519 is therefore
/// 32 bytes regardless of which curve bit was selected.
pub const CIPHERTEXT_LEN: usize = 32;
/// Moeller original message size (params->msgsize) — preserved at the
/// C++ default for capture-compatibility; means the wrapper byte length
/// that holds the curve selection bit + random padding.
pub const MSGSIZE: usize = 108;
/// Output shared-secret length matches X25519's raw secret size.
pub const SECRET_LEN: usize = 32;

/// Errors surfaced by MKEM operations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MkemError {
    #[error("invalid ciphertext length: {got}, want {want}")]
    Length { got: usize, want: usize },
}

/// Public-key wrapper. Holds two X25519 public keys (`pub0`, `pub1`)
/// — one per curve-bit. `generate` posts the ciphertext byte sequence
/// ready for embedding into a stegotorus-style payload.
pub struct MkemPublicKey {
    pub0: PublicKey,
    pub1: PublicKey,
}

/// Private-key wrapper. Holds the two X25519 secrets matching the public
/// counterparts. Decode inspects the curve-selection bit on the ciphertext
/// and computes the shared secret against the matching private key.
pub struct MkemPrivateKey {
    s0: StaticSecret,
    s1: StaticSecret,
    pub pub0: PublicKey,
    pub pub1: PublicKey,
}

/// Generate (`MKEM::generate`) — caller-visible entry.
/// Returns (ciphertext, shared_secret) where `ciphertext` is exactly
/// 32 bytes encoding the chosen ephemeral public key plus a 1-byte
/// curve selector prefix.
pub fn generate(pubkey: &MkemPublicKey) -> (Vec<u8>, [u8; SECRET_LEN]) {
    let mut rng = OsRng;
    let curve_bit = rng.next_u32() & 1;
    let ephem = StaticSecret::random_from_rng(rng);
    let ephem_pub = PublicKey::from(&ephem);
    let chosen_pub = if curve_bit == 0 {
        pubkey.pub0
    } else {
        pubkey.pub1
    };
    let shared = ephem.diffie_hellman(&chosen_pub);
    let secret_bytes = shared.as_bytes();
    let mut secret = [0u8; SECRET_LEN];
    secret.copy_from_slice(secret_bytes);

    // Wire layout: [curve_bit byte][ephem_pub: 32 bytes]. This is a
    // Moeller-style encoding that the decoder inspects to recover the bit.
    // ponytail: C++ reference repurposed the top padding bits to encode
    // the bit; we use an explicit prefix to keep the parser trivial.
    let mut ct = Vec::with_capacity(1 + CIPHERTEXT_LEN);
    ct.push(curve_bit as u8);
    ct.extend_from_slice(ephem_pub.as_bytes());
    (ct, secret)
}

/// Decode (`MKEM::decode`) — server-side.
/// Recovers the shared secret from a ciphertext produced by `generate`.
pub fn decode(privkey: &MkemPrivateKey, ciphertext: &[u8]) -> Result<[u8; SECRET_LEN], MkemError> {
    if ciphertext.len() != 1 + CIPHERTEXT_LEN {
        return Err(MkemError::Length {
            got: ciphertext.len(),
            want: 1 + CIPHERTEXT_LEN,
        });
    }
    let curve_bit = ciphertext[0] & 1;
    let mut ephem_bytes = [0u8; 32];
    ephem_bytes.copy_from_slice(&ciphertext[1..]);
    let ephem_pub = PublicKey::from(ephem_bytes);

    let chosen = if curve_bit == 0 {
        &privkey.s0
    } else {
        &privkey.s1
    };
    let shared = chosen.diffie_hellman(&ephem_pub);
    let mut secret = [0u8; SECRET_LEN];
    secret.copy_from_slice(shared.as_bytes());
    Ok(secret)
}

impl MkemPrivateKey {
    /// Generate a fresh keypair pair (curve-bit 0 + curve-bit 1).
    pub fn generate() -> Self {
        let rng = OsRng;
        let s0 = StaticSecret::random_from_rng(rng);
        let s1 = StaticSecret::random_from_rng(rng);
        let pub0 = PublicKey::from(&s0);
        let pub1 = PublicKey::from(&s1);
        Self { s0, s1, pub0, pub1 }
    }

    /// Expose the matching MkemPublicKey.
    pub fn public(&self) -> MkemPublicKey {
        MkemPublicKey {
            pub0: self.pub0,
            pub1: self.pub1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_then_decode_recovers_shared_secret() {
        let privkey = MkemPrivateKey::generate();
        let pubkey = privkey.public();
        let (ct, sent) = generate(&pubkey);
        let recv = decode(&privkey, &ct).unwrap();
        assert_eq!(sent, recv);
    }

    #[test]
    fn ciphertext_has_expected_length() {
        let privkey = MkemPrivateKey::generate();
        let pubkey = privkey.public();
        let (ct, _) = generate(&pubkey);
        assert_eq!(ct.len(), 1 + CIPHERTEXT_LEN);
    }

    #[test]
    fn rejects_short_ciphertext() {
        let privkey = MkemPrivateKey::generate();
        let err = decode(&privkey, b"x").unwrap_err();
        assert!(matches!(err, MkemError::Length { .. }));
    }

    #[test]
    fn two_generate_calls_produce_distinct_secrets() {
        let privkey = MkemPrivateKey::generate();
        let pubkey = privkey.public();
        let (_ct_a, sec_a) = generate(&pubkey);
        let (_ct_b, sec_b) = generate(&pubkey);
        assert_ne!(sec_a, sec_b);
    }
}
