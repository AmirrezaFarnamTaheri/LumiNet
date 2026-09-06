
use ring::aead::{self, LessSafeKey, UnboundKey};
use ring::agreement::{self, EphemeralPrivateKey};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct CloakObfs {
    pub active: bool,
}

#[derive(Debug)]
pub struct AuthInfo {
    pub uid: [u8; 16],
    pub proxy_method: [u8; 12],
    pub encryption_method: u8,
    pub session_id: u32,
    pub unordered: bool,
    pub server_pub_key: [u8; 32],
}

pub struct AuthenticationPayload {
    pub rand_pub_key: [u8; 32],
    pub ciphertext_with_tag: [u8; 64],
}

impl Default for CloakObfs {
    fn default() -> Self {
        Self::new()
    }
}

impl CloakObfs {
    pub fn new() -> Self {
        CloakObfs { active: true }
    }

    /// Generates Cloak authentication payload matching client/auth.go
    pub fn make_auth_payload(
        &self,
        info: &AuthInfo,
    ) -> Result<AuthenticationPayload, ring::error::Unspecified> {
        let rng = ring::rand::SystemRandom::new();

        // 1. Generate Ephemeral X25519 Keypair
        let my_private_key = EphemeralPrivateKey::generate(&agreement::X25519, &rng)?;
        let my_public_key = my_private_key.compute_public_key()?;

        let mut rand_pub_key = [0u8; 32];
        rand_pub_key.copy_from_slice(my_public_key.as_ref());

        // 2. Perform ECDH Agreement with server public key
        let peer_public_key =
            agreement::UnparsedPublicKey::new(&agreement::X25519, &info.server_pub_key);

        let shared_secret =
            agreement::agree_ephemeral(my_private_key, &peer_public_key, |key_material| {
                let mut secret = [0u8; 32];
                secret.copy_from_slice(key_material);
                secret
            })?;

        // 3. Compose plaintext payload
        let mut plaintext = [0u8; 48];
        plaintext[0..16].copy_from_slice(&info.uid);
        plaintext[16..28].copy_from_slice(&info.proxy_method);
        plaintext[28] = info.encryption_method;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        plaintext[29..37].copy_from_slice(&now.to_be_bytes());
        plaintext[37..41].copy_from_slice(&info.session_id.to_be_bytes());

        if info.unordered {
            plaintext[41] |= 0x01; // UNORDERED_FLAG
        }

        // 4. Encrypt using AES-256-GCM.
        // We use the first 12 bytes of the ephemeral public key as the GCM Nonce,
        // and the ECDH shared secret as the AES Key.
        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &shared_secret)?;
        let safe_key = LessSafeKey::new(unbound_key);

        let nonce_slice = &rand_pub_key[0..12];
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce_slice)?;

        // Ciphertext space must be large enough to hold plaintext (48 bytes) + GCM tag (16 bytes) = 64 bytes
        let mut ciphertext_with_tag = [0u8; 64];
        ciphertext_with_tag[0..48].copy_from_slice(&plaintext);

        let tag = safe_key.seal_in_place_separate_tag(
            nonce,
            aead::Aad::empty(),
            &mut ciphertext_with_tag[0..48],
        )?;

        ciphertext_with_tag[48..64].copy_from_slice(tag.as_ref());

        Ok(AuthenticationPayload {
            rand_pub_key,
            ciphertext_with_tag,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_auth_payload() {
        let obfs = CloakObfs::new();
        let server_private =
            EphemeralPrivateKey::generate(&agreement::X25519, &ring::rand::SystemRandom::new())
                .unwrap();
        let server_pub = server_private.compute_public_key().unwrap();
        let mut server_pub_bytes = [0u8; 32];
        server_pub_bytes.copy_from_slice(server_pub.as_ref());

        let info = AuthInfo {
            uid: [7u8; 16],
            proxy_method: *b"shadowsocks\0",
            encryption_method: 3,
            session_id: 12345,
            unordered: true,
            server_pub_key: server_pub_bytes,
        };

        let result = obfs.make_auth_payload(&info);
        assert!(result.is_ok());
        let payload = result.unwrap();
        assert_ne!(payload.rand_pub_key, [0u8; 32]);
        assert_ne!(payload.ciphertext_with_tag, [0u8; 64]);
    }
}
