use ml_dsa::{Generate, Keypair, MlDsa65, Signer, SigningKey, Verifier, VerifyingKey};
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    EncodedSizeUser, KemCore, MlKem768, MlKem768Params,
};

/// Generates a new ML-KEM-768 public/private keypair.
/// Returns (public_key_bytes, private_key_bytes).
pub fn generate_mlkem768_keypair() -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut rng = rand::thread_rng();
    let (dk, ek) = MlKem768::generate(&mut rng);

    let ek_bytes = ek.as_bytes().as_slice().to_vec();
    let dk_bytes = dk.as_bytes().as_slice().to_vec();

    Ok((ek_bytes, dk_bytes))
}

/// Generates a shared secret and ciphertext using the public key.
/// Returns (shared_secret_bytes, ciphertext_bytes).
pub fn mlkem768_encapsulate(pub_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let pub_key_bytes: [u8; 1184] = pub_key
        .try_into()
        .map_err(|_| "Invalid ML-KEM-768 public key size, expected 1184 bytes".to_string())?;

    let enc_ek =
        ml_kem::Encoded::<ml_kem::kem::EncapsulationKey<MlKem768Params>>::from(pub_key_bytes);
    let ek = ml_kem::kem::EncapsulationKey::<MlKem768Params>::from_bytes(&enc_ek);

    let mut rng = rand::thread_rng();
    let (ciphertext, secret) = ek
        .encapsulate(&mut rng)
        .map_err(|e| format!("ML-KEM-768 encapsulation failed: {:?}", e))?;

    Ok((secret.as_slice().to_vec(), ciphertext.as_slice().to_vec()))
}

/// Recovers the shared secret from the ciphertext using the private key.
pub fn mlkem768_decapsulate(priv_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let priv_key_bytes: [u8; 2400] = priv_key
        .try_into()
        .map_err(|_| "Invalid ML-KEM-768 private key size, expected 2400 bytes".to_string())?;

    let enc_dk =
        ml_kem::Encoded::<ml_kem::kem::DecapsulationKey<MlKem768Params>>::from(priv_key_bytes);
    let dk = ml_kem::kem::DecapsulationKey::<MlKem768Params>::from_bytes(&enc_dk);

    let ct_bytes: [u8; 1088] = ciphertext
        .try_into()
        .map_err(|_| "Invalid ML-KEM-768 ciphertext size, expected 1088 bytes".to_string())?;

    let ct = ml_kem::Ciphertext::<MlKem768>::from(ct_bytes);

    let secret = dk
        .decapsulate(&ct)
        .map_err(|e| format!("ML-KEM-768 decapsulation failed: {:?}", e))?;

    Ok(secret.as_slice().to_vec())
}

/// Generates a new ML-DSA-65 keypair for signing and verification.
/// Returns (public_key_bytes, private_key_bytes).
pub fn generate_mldsa65_keypair() -> Result<(Vec<u8>, Vec<u8>), String> {
    let sk = SigningKey::<MlDsa65>::generate();
    let pk = sk.verifying_key();

    let pk_bytes = pk.encode().as_slice().to_vec();
    let sk_bytes = sk.to_seed().as_slice().to_vec();

    Ok((pk_bytes, sk_bytes))
}

/// Signs the message with the private key (32-byte seed) and returns the signature.
pub fn mldsa65_sign(priv_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let seed_bytes: [u8; 32] = priv_key
        .try_into()
        .map_err(|_| "Invalid private key size, expected 32-byte seed".to_string())?;

    let seed = ml_dsa::Seed::from(seed_bytes);
    let sk = SigningKey::<MlDsa65>::from_seed(&seed);

    let sig = sk.sign(message);

    Ok(sig.encode().as_slice().to_vec())
}

/// Verifies the signature on the message using the public key.
pub fn mldsa65_verify(pub_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, String> {
    let pk_bytes: [u8; 1952] = pub_key
        .try_into()
        .map_err(|_| "Invalid public key size, expected 1952 bytes".to_string())?;

    let enc_pk = ml_dsa::EncodedVerifyingKey::<MlDsa65>::from(pk_bytes);
    let pk = VerifyingKey::<MlDsa65>::decode(&enc_pk);

    let sig_bytes: [u8; 3309] = signature
        .try_into()
        .map_err(|_| "Invalid signature size, expected 3309 bytes".to_string())?;

    let enc_sig = ml_dsa::EncodedSignature::<MlDsa65>::from(sig_bytes);
    let sig = ml_dsa::Signature::<MlDsa65>::decode(&enc_sig)
        .ok_or_else(|| "Failed to decode signature".to_string())?;

    match pk.verify(message, &sig) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Derives a hybrid shared secret from ML-KEM-768 and X25519 shared secrets.
pub fn derive_hybrid_shared_secret(
    mlkem_secret: &[u8],
    x25519_secret: &[u8],
) -> Result<Vec<u8>, String> {
    if mlkem_secret.len() != 32 {
        return Err("invalid ML-KEM-768 secret size, expected 32 bytes".to_string());
    }
    if x25519_secret.len() != 32 {
        return Err("invalid X25519 secret size, expected 32 bytes".to_string());
    }
    let mut combined = vec![0u8; 64];
    combined[0..32].copy_from_slice(mlkem_secret);
    combined[32..64].copy_from_slice(x25519_secret);
    Ok(combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_mlkem768() {
        let (pub_key, priv_key) = generate_mlkem768_keypair().unwrap();
        assert_eq!(pub_key.len(), 1184);
        assert_eq!(priv_key.len(), 2400);

        let (secret, ciphertext) = mlkem768_encapsulate(&pub_key).unwrap();
        assert_eq!(secret.len(), 32);
        assert_eq!(ciphertext.len(), 1088);

        let recovered = mlkem768_decapsulate(&priv_key, &ciphertext).unwrap();
        assert_eq!(secret, recovered);
    }

    #[test]
    fn test_rust_mldsa65() {
        let (pub_key, priv_key) = generate_mldsa65_keypair().unwrap();
        assert_eq!(pub_key.len(), 1952);
        assert_eq!(priv_key.len(), 32); // 32-byte seed representation

        let msg = b"Post-quantum Rust test message";
        let sig = mldsa65_sign(&priv_key, msg).unwrap();
        assert_eq!(sig.len(), 3309);

        let valid = mldsa65_verify(&pub_key, msg, &sig).unwrap();
        assert!(valid);

        // Tamper test
        let tampered = b"Post-quantum Rust test message tampered";
        let valid_tampered = mldsa65_verify(&pub_key, tampered, &sig).unwrap();
        assert!(!valid_tampered);
    }

    #[test]
    fn test_rust_derive_hybrid() {
        let mlkem = vec![7u8; 32];
        let x25519 = vec![9u8; 32];
        let combined = derive_hybrid_shared_secret(&mlkem, &x25519).unwrap();
        assert_eq!(combined.len(), 64);
        assert_eq!(&combined[0..32], &mlkem[..]);
        assert_eq!(&combined[32..64], &x25519[..]);
    }
}
