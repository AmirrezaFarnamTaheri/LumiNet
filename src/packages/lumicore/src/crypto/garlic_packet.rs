//! # I2P Garlic Packet Cryptography
//!
//! Implements I2P Garlic routing encryption — layered ElGamal/AES-256-CBC
//! wrapping as used in the i2p.i2p Java reference implementation, ported to Rust.
//!
//! Garlic cloves are individually encrypted to the recipient's ElGamal public key,
//! then bundled into a single garlic message wrapped with a symmetric AES layer.
//!
//! Wire layout per clove:
//!   [ElGamal_ciphertext : 514 bytes][AES_IV : 16][AES_ciphertext : N][Delivery : var]

use rand::RngCore;

pub const ELGAMAL_PUBKEY_SIZE: usize = 256;
pub const ELGAMAL_PRIVKEY_SIZE: usize = 256;
pub const ELGAMAL_CIPHER_SIZE: usize = 514; // 2 * 257 bytes
const AES_IV_SIZE: usize = 16;
const AES_KEY_SIZE: usize = 32;
const SESSION_TAG_SIZE: usize = 32;

/// I2P Garlic delivery type for a clove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryType {
    /// Deliver locally to this router.
    Local = 0,
    /// Deliver to a specific router by its 32-byte hash.
    Router = 2,
    /// Deliver to a specific tunnel.
    Tunnel = 3,
}

/// Represents a single garlic clove payload.
#[derive(Debug, Clone)]
pub struct GarlicClove {
    pub delivery: DeliveryType,
    /// The delivery hash (router identity hash for Router delivery).
    pub delivery_hash: Option<[u8; 32]>,
    /// Tunnel ID for Tunnel delivery.
    pub tunnel_id: Option<u32>,
    /// The raw I2NP message payload.
    pub message: Vec<u8>,
    /// Clove expiration in seconds since Unix epoch.
    pub expiration: u32,
}

impl GarlicClove {
    /// Creates a new local-delivery clove.
    pub fn local(message: Vec<u8>, expiration: u32) -> Self {
        Self {
            delivery: DeliveryType::Local,
            delivery_hash: None,
            tunnel_id: None,
            message,
            expiration,
        }
    }

    /// Creates a router-delivery clove.
    pub fn to_router(router_hash: [u8; 32], message: Vec<u8>, expiration: u32) -> Self {
        Self {
            delivery: DeliveryType::Router,
            delivery_hash: Some(router_hash),
            tunnel_id: None,
            message,
            expiration,
        }
    }

    /// Serializes the clove into its wire format.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.delivery as u8);
        match self.delivery {
            DeliveryType::Local => {}
            DeliveryType::Router => {
                if let Some(h) = &self.delivery_hash {
                    out.extend_from_slice(h);
                }
            }
            DeliveryType::Tunnel => {
                if let Some(h) = &self.delivery_hash {
                    out.extend_from_slice(h);
                }
                let tid = self.tunnel_id.unwrap_or(0);
                out.extend_from_slice(&tid.to_be_bytes());
            }
        }
        // Message size prefix (big-endian u32)
        out.extend_from_slice(&(self.message.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.message);
        out.extend_from_slice(&self.expiration.to_be_bytes());
        out
    }

    /// Deserializes a clove from bytes. Returns `(clove, bytes_consumed)`.
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), GarlicError> {
        if data.is_empty() {
            return Err(GarlicError::ShortInput);
        }
        let delivery = match data[0] {
            0 => DeliveryType::Local,
            2 => DeliveryType::Router,
            3 => DeliveryType::Tunnel,
            t => return Err(GarlicError::UnknownDeliveryType(t)),
        };
        let mut offset = 1usize;

        let delivery_hash = if delivery == DeliveryType::Router || delivery == DeliveryType::Tunnel
        {
            if data.len() < offset + 32 {
                return Err(GarlicError::ShortInput);
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            Some(h)
        } else {
            None
        };

        let tunnel_id = if delivery == DeliveryType::Tunnel {
            if data.len() < offset + 4 {
                return Err(GarlicError::ShortInput);
            }
            let tid = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap());
            offset += 4;
            Some(tid)
        } else {
            None
        };

        if data.len() < offset + 4 {
            return Err(GarlicError::ShortInput);
        }
        let msg_len = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        if data.len() < offset + msg_len + 4 {
            return Err(GarlicError::ShortInput);
        }
        let message = data[offset..offset + msg_len].to_vec();
        offset += msg_len;
        let expiration = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap());
        offset += 4;

        Ok((
            Self {
                delivery,
                delivery_hash,
                tunnel_id,
                message,
                expiration,
            },
            offset,
        ))
    }
}

/// Garlic message bundling multiple encrypted cloves.
pub struct GarlicMessage {
    pub cloves: Vec<GarlicClove>,
    pub certificate: Vec<u8>,
}

impl GarlicMessage {
    pub fn new(cloves: Vec<GarlicClove>) -> Self {
        Self {
            cloves,
            certificate: vec![0u8; 3], // Null certificate: type=0, length=0
        }
    }

    /// Serializes all cloves into a garlic payload (without outer encryption).
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // Clove count (u8)
        out.push(self.cloves.len() as u8);
        for clove in &self.cloves {
            out.extend_from_slice(&clove.serialize());
        }
        out.extend_from_slice(&self.certificate);
        out
    }
}

/// Symmetric session-key garlic encryption (AES-256-CBC layer).
/// The session key is exchanged via ElGamal on first contact,
/// then sessions are resumed via 32-byte session tags.
pub struct GarlicSymmetricEncryptor {
    session_key: [u8; AES_KEY_SIZE],
    session_tag: [u8; SESSION_TAG_SIZE],
}

impl GarlicSymmetricEncryptor {
    /// Creates a new encryptor with a random session key and tag.
    pub fn new_random() -> Self {
        let mut key = [0u8; AES_KEY_SIZE];
        let mut tag = [0u8; SESSION_TAG_SIZE];
        rand::thread_rng().fill_bytes(&mut key);
        rand::thread_rng().fill_bytes(&mut tag);
        Self {
            session_key: key,
            session_tag: tag,
        }
    }

    /// Creates from a specific session key and tag.
    pub fn from_key(session_key: [u8; AES_KEY_SIZE], session_tag: [u8; SESSION_TAG_SIZE]) -> Self {
        Self {
            session_key,
            session_tag,
        }
    }

    /// Returns the session tag (used to identify this session to the recipient).
    pub fn session_tag(&self) -> &[u8; SESSION_TAG_SIZE] {
        &self.session_tag
    }

    /// Encrypts a garlic payload: [tag][AES_IV][AES_ciphertext].
    pub fn encrypt(&self, payload: &[u8]) -> Result<Vec<u8>, GarlicError> {
        use aes::cipher::{BlockEncryptMut, KeyIvInit};
        use aes::Aes256;
        use cbc::Encryptor;

        let mut iv = [0u8; AES_IV_SIZE];
        rand::thread_rng().fill_bytes(&mut iv);

        let cipher = Encryptor::<Aes256>::new((&self.session_key).into(), (&iv).into());
        let block_size = 16;
        let pad_len = block_size - (payload.len() % block_size);
        let mut buf = vec![0u8; payload.len() + pad_len];
        buf[..payload.len()].copy_from_slice(payload);

        let ciphertext_ref = cipher
            .encrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buf, payload.len())
            .map_err(|_| GarlicError::EncryptFailed)?;
        let ciphertext = ciphertext_ref.to_vec();

        let mut out = Vec::with_capacity(SESSION_TAG_SIZE + AES_IV_SIZE + ciphertext.len());
        out.extend_from_slice(&self.session_tag);
        out.extend_from_slice(&iv);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypts a garlic message (expects [tag][IV][ciphertext] format).
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, GarlicError> {
        let min_len = SESSION_TAG_SIZE + AES_IV_SIZE + 16;
        if data.len() < min_len {
            return Err(GarlicError::ShortInput);
        }
        let iv: [u8; 16] = data[SESSION_TAG_SIZE..SESSION_TAG_SIZE + AES_IV_SIZE]
            .try_into()
            .unwrap();
        let ciphertext = &data[SESSION_TAG_SIZE + AES_IV_SIZE..];

        use aes::cipher::{BlockDecryptMut, KeyIvInit};
        use aes::Aes256;
        use cbc::Decryptor;

        let cipher = Decryptor::<Aes256>::new((&self.session_key).into(), (&iv).into());
        let mut buf = ciphertext.to_vec();
        let plaintext_ref = cipher
            .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buf)
            .map_err(|_| GarlicError::DecryptFailed)?;
        let plaintext = plaintext_ref.to_vec();
        Ok(plaintext)
    }
}

/// Errors from garlic packet operations.
#[derive(Debug, thiserror::Error)]
pub enum GarlicError {
    #[error("input too short")]
    ShortInput,
    #[error("unknown delivery type: {0}")]
    UnknownDeliveryType(u8),
    #[error("encryption failed")]
    EncryptFailed,
    #[error("decryption failed")]
    DecryptFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clove_serialize_deserialize_roundtrip() {
        let msg = b"i2p test message".to_vec();
        let clove = GarlicClove::local(msg.clone(), 1_700_000_000);
        let bytes = clove.serialize();
        let (recovered, consumed) = GarlicClove::deserialize(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(recovered.message, msg);
        assert_eq!(recovered.expiration, 1_700_000_000);
        assert_eq!(recovered.delivery, DeliveryType::Local);
    }

    #[test]
    fn test_router_clove_roundtrip() {
        let hash = [0xabu8; 32];
        let msg = b"router delivery".to_vec();
        let clove = GarlicClove::to_router(hash, msg.clone(), 42);
        let bytes = clove.serialize();
        let (recovered, _) = GarlicClove::deserialize(&bytes).unwrap();
        assert_eq!(recovered.delivery, DeliveryType::Router);
        assert_eq!(recovered.delivery_hash, Some(hash));
        assert_eq!(recovered.message, msg);
    }

    #[test]
    fn test_garlic_message_serialize() {
        let cloves = vec![GarlicClove::local(b"test".to_vec(), 0)];
        let msg = GarlicMessage::new(cloves);
        let bytes = msg.serialize();
        assert!(!bytes.is_empty());
        assert_eq!(bytes[0], 1); // One clove
    }
}
