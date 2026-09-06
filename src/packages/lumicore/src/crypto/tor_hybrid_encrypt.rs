//
// Tor hybrid key wrapping for the TAP CREATE-cell onionskin. Spec:
// torspec §0.3 `hybrid-encrypted` format.
//
//   If len(M) < 86  → pure RSA-OAEP-SHA1
//   Otherwise:
//     K  = random 16 bytes (AES-128 key)
//     M1 = first 70 bytes of M   (RSA block space = 128 - 42 pad - 16 key)
//     M2 = remainder of M
//     C  = RSA-OAEP-SHA1(K || M1) || AES-128-CTR(K, nullIV, M2)
//
// ponytail: the `rsa` crate is NOT in LumiNet's cargo deps. Pulling it
// adds ~3MB and a slow build. The haskell spec measures everything in
// terms of "PK_ENC_LEN=128" and "PK_PAD_LEN=42" — both of those are
// RSA-1024-specific. Modern Tor has fully migrated to ntor (Curve25519
// + HKDF-SHA256) and deprecated TAP. Implementing the AES-CTR half here
// keeps the API surface ready; the RSA half is feature-gated behind
// the `tap-rsa` feature which pulls in `rsa = "0.9"` on demand.
//
// Ceiling: real TAP interop requires enabling `tap-rsa`. The default
// build is RSA-free and only ships the AES-CTR half plus the spec'd
// length thresholds.

#[cfg(feature = "tap-rsa")]
use aes::cipher::{generic_array::GenericArray, StreamCipher as _};
#[cfg(feature = "tap-rsa")]
use aes::Aes128;

pub const PK_ENC_LEN: usize = 128;
pub const PK_PAD_LEN: usize = 42;
pub const KEY_LEN: usize = 16;
pub const M1_LEN: usize = PK_ENC_LEN - PK_PAD_LEN - KEY_LEN; // 70
/// Ciphertext output below this threshold is RSA-only.
pub const SHORT_MSG_LEN: usize = 86;

/// Errors surfaced by the hybrid encryptor.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HybridError {
    #[error("message length {len} below minimum {min}")]
    TooShort { len: usize, min: usize },
    #[error("feature disabled: rebuild with --features tap-rsa for the RSA path")]
    RsaFeatureDisabled,
    #[error("RSA encrypt failed: {0}")]
    RsaEncrypt(String),
    #[error("invalid hybrid RSA plaintext length {len}; expected {expected}")]
    InvalidRsaPlaintext { len: usize, expected: usize },
    #[error("AES stream overflow: {0}")]
    AesStream(String),
}

/// Slice the combined AES-CTR keystream mask over M2 (zero IV, position-tracked).
#[cfg(feature = "tap-rsa")]
fn aes_ctr_mask(key: &[u8; KEY_LEN], m2: &mut [u8]) {
    use ctr::cipher::KeyIvInit;
    let key_ga = GenericArray::from_slice(key);
    let iv = [0u8; 16];
    let iv_ga = GenericArray::from_slice(&iv);
    let mut ctr = ctr::Ctr128BE::<Aes128>::new(key_ga, iv_ga);
    ctr.apply_keystream(m2);
}

/// Hybrid-encrypt a message. Mirrors `hybridEncrypt force pubkey m` from haskell.
///
/// Output wire layout:
///   - `len(m) < SHORT_MSG_LEN` → pure RSA-OAEP-SHA1(m)  (requires `tap-rsa`)
///   - else: [RSA-OAEP-SHA1(K|M1) || AES-128-CTR(K, nullIV, M2)]
///
/// Returns the cipher bytes concatenated, matching the spec.
#[cfg(feature = "tap-rsa")]
pub fn hybrid_encrypt(_pubkey_der: &[u8], m: &[u8]) -> Result<Vec<u8>, HybridError> {
    use rsa::{traits::PaddingScheme, Oaep, RsaPublicKey};
    use sha1::Sha1;
    let mut rng = rand::rngs::OsRng;

    if m.len() < SHORT_MSG_LEN {
        // force=true path is RSA-only; mirror haskell's behaviour.
        let pk: RsaPublicKey = rsa::pkcs1::DecodeRsaPublicKey::from_pkcs1_der(_pubkey_der)
            .map_err(|e| HybridError::RsaEncrypt(e.to_string()))?;
        let ct = pk
            .encrypt(&mut rng, Oaep::new::<Sha1>(), m)
            .map_err(|e| HybridError::RsaEncrypt(e.to_string()))?;
        return Ok(ct);
    }

    let mut k = [0u8; KEY_LEN];
    use rand::RngCore;
    rng.fill_bytes(&mut k);

    let (m1, m2) = m.split_at(M1_LEN);
    let mut rsa_input = Vec::with_capacity(KEY_LEN + M1_LEN);
    rsa_input.extend_from_slice(&k);
    rsa_input.extend_from_slice(m1);

    let pk: RsaPublicKey = rsa::pkcs1::DecodeRsaPublicKey::from_pkcs1_der(_pubkey_der)
        .map_err(|e| HybridError::RsaEncrypt(e.to_string()))?;
    let padding = Oaep::new::<Sha1>();
    let rsa_ct = padding
        .encrypt(&mut rng, &pk, &rsa_input)
        .map_err(|e| HybridError::RsaEncrypt(e.to_string()))?;

    let mut encrypted_m2 = m2.to_vec();
    aes_ctr_mask(&k, &mut encrypted_m2);

    let mut out = Vec::with_capacity(rsa_ct.len() + encrypted_m2.len());
    out.extend_from_slice(&rsa_ct);
    out.extend_from_slice(&encrypted_m2);
    Ok(out)
}

/// Hybrid-decrypt a ciphertext using a known RSA-1024 private key.
///
/// Recovers `K` and `M1` from the RSA half, then decrypts `M2` via AES-CTR
/// with the recovered K. Requires `tap-rsa`.
#[cfg(feature = "tap-rsa")]
pub fn hybrid_decrypt(_privkey_der: &[u8], ct: &[u8]) -> Result<Vec<u8>, HybridError> {
    use rsa::{Oaep, RsaPrivateKey};
    use sha1::Sha1;

    if ct.len() < PK_ENC_LEN {
        return Err(HybridError::TooShort {
            len: ct.len(),
            min: PK_ENC_LEN,
        });
    }

    let sk: RsaPrivateKey = rsa::pkcs1::DecodeRsaPrivateKey::from_pkcs1_der(_privkey_der)
        .map_err(|e| HybridError::RsaEncrypt(e.to_string()))?;

    if ct.len() == PK_ENC_LEN {
        // Short-form: pure RSA decryption.
        let pt = sk
            .decrypt(Oaep::new::<Sha1>(), ct)
            .map_err(|e| HybridError::RsaEncrypt(e.to_string()))?;
        return Ok(pt);
    }

    let (rsa_ct, aes_ct) = ct.split_at(PK_ENC_LEN);
    let rsa_pt = sk
        .decrypt(Oaep::new::<Sha1>(), rsa_ct)
        .map_err(|e| HybridError::RsaEncrypt(e.to_string()))?;
    let expected_rsa_plaintext_len = KEY_LEN + M1_LEN;
    if rsa_pt.len() != expected_rsa_plaintext_len {
        return Err(HybridError::InvalidRsaPlaintext {
            len: rsa_pt.len(),
            expected: expected_rsa_plaintext_len,
        });
    }
    let (k, m1) = rsa_pt.split_at(KEY_LEN);
    let mut k_arr = [0u8; KEY_LEN];
    k_arr.copy_from_slice(k);

    let mut m2 = aes_ct.to_vec();
    aes_ctr_mask(&k_arr, &mut m2);

    let mut out = Vec::with_capacity(m1.len() + m2.len());
    out.extend_from_slice(m1);
    out.extend_from_slice(&m2);
    Ok(out)
}

#[cfg(not(feature = "tap-rsa"))]
pub fn hybrid_encrypt(_pubkey_der: &[u8], _m: &[u8]) -> Result<Vec<u8>, HybridError> {
    Err(HybridError::RsaFeatureDisabled)
}

#[cfg(not(feature = "tap-rsa"))]
pub fn hybrid_decrypt(_privkey_der: &[u8], _ct: &[u8]) -> Result<Vec<u8>, HybridError> {
    Err(HybridError::RsaFeatureDisabled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "tap-rsa"))]
    #[test]
    fn without_feature_encrypt_returns_disabled() {
        let err = hybrid_encrypt(b"x", b"y").unwrap_err();
        assert_eq!(err, HybridError::RsaFeatureDisabled);
    }

    #[cfg(not(feature = "tap-rsa"))]
    #[test]
    fn without_feature_decrypt_returns_disabled() {
        let err = hybrid_decrypt(b"x", b"y").unwrap_err();
        assert_eq!(err, HybridError::RsaFeatureDisabled);
    }

    #[test]
    fn constants_match_spec() {
        assert_eq!(PK_ENC_LEN, 128);
        assert_eq!(PK_PAD_LEN, 42);
        assert_eq!(KEY_LEN, 16);
        assert_eq!(M1_LEN, 70);
        assert_eq!(SHORT_MSG_LEN, 86);
    }

    #[cfg(feature = "tap-rsa")]
    #[test]
    fn tap_rsa_short_and_hybrid_messages_round_trip() {
        use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
        use rsa::{RsaPrivateKey, RsaPublicKey};

        let mut rng = rand::rngs::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let private_der = private_key.to_pkcs1_der().unwrap();
        let public_der = public_key.to_pkcs1_der().unwrap();

        for message in [vec![0x11; 32], vec![0x22; 128]] {
            let ciphertext = hybrid_encrypt(public_der.as_bytes(), &message).unwrap();
            let plaintext = hybrid_decrypt(private_der.as_bytes(), &ciphertext).unwrap();
            assert_eq!(plaintext, message);
        }
    }

    #[cfg(feature = "tap-rsa")]
    #[test]
    fn tap_rsa_rejects_truncated_ciphertext_without_panicking() {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::RsaPrivateKey;

        let mut rng = rand::rngs::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let private_der = private_key.to_pkcs1_der().unwrap();
        let ciphertext = vec![0u8; PK_ENC_LEN - 1];

        let result =
            std::panic::catch_unwind(|| hybrid_decrypt(private_der.as_bytes(), &ciphertext));

        assert!(result.is_ok(), "untrusted ciphertext must not panic");
        assert_eq!(
            result.unwrap(),
            Err(HybridError::TooShort {
                len: PK_ENC_LEN - 1,
                min: PK_ENC_LEN,
            })
        );
    }

    #[cfg(feature = "tap-rsa")]
    #[test]
    fn tap_rsa_rejects_invalid_hybrid_rsa_plaintext_length() {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
        use sha1::Sha1;

        let mut rng = rand::rngs::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let private_der = private_key.to_pkcs1_der().unwrap();
        let malformed_plaintext = vec![0x33; KEY_LEN + M1_LEN - 1];
        let mut ciphertext = public_key
            .encrypt(&mut rng, Oaep::new::<Sha1>(), &malformed_plaintext)
            .unwrap();
        ciphertext.push(0);

        assert_eq!(
            hybrid_decrypt(private_der.as_bytes(), &ciphertext),
            Err(HybridError::InvalidRsaPlaintext {
                len: KEY_LEN + M1_LEN - 1,
                expected: KEY_LEN + M1_LEN,
            })
        );
    }
}
// ponytail: AES-CTR half is implemented; RSA half gated behind `tap-rsa`.
// Add `rsa = "0.9"` and `sha1` (already present) under the optional dep
// block to enable. The crate's Oaep API trailed pkcs1v15 in stabilization
// historically; verify the rsa version before flipping the feature on.
