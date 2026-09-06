//! Encrypted Payload Envelope Codec & Secure IP List Provider.
//!
//! Implements authenticated encryption/decryption of configuration payloads and IP lists
//! using AES-256-GCM, SHA-256 passphrase key derivation, and URL-safe Base64 encoding.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::str::FromStr;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnvelopeError {
    #[error("Decryption passphrase cannot be blank")]
    BlankPassphrase,
    #[error("Invalid JSON envelope: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Unsupported envelope version: expected {expected}, got {actual}")]
    UnsupportedVersion { expected: u32, actual: u32 },
    #[error("Unsupported envelope algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("Unsupported envelope encoding: {0}")]
    UnsupportedEncoding(String),
    #[error("Base64 decoding failed: {0}")]
    Base64Error(String),
    #[error("Cryptographic authentication/decryption failed: {0}")]
    CryptoError(String),
    #[error("Decrypted payload is not valid UTF-8: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
    #[error("Decrypted IP list contained no usable IPv4 addresses")]
    EmptyIpList,
}

/// Version 1 AES-256-GCM encrypted payload envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EncryptedPayloadEnvelope {
    pub version: u32,
    pub algorithm: String,
    pub encoding: String,
    pub iv: String,
    pub ciphertext: String,
}

pub struct EncryptedPayloadCodec;

impl EncryptedPayloadCodec {
    pub const SUPPORTED_VERSION: u32 = 1;
    pub const SUPPORTED_ALGORITHM: &'static str = "AES-GCM";
    pub const SUPPORTED_ENCODING: &'static str = "base64url";

    /// Derives an AES-256 key from a passphrase using SHA-256.
    pub fn derive_key(passphrase: &str) -> Result<[u8; 32], EnvelopeError> {
        if passphrase.trim().is_empty() {
            return Err(EnvelopeError::BlankPassphrase);
        }
        let mut hasher = Sha256::new();
        hasher.update(passphrase.as_bytes());
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        Ok(key)
    }

    /// Encrypts raw plaintext using AES-256-GCM and generates an envelope JSON string.
    pub fn encrypt(plaintext: &[u8], passphrase: &str) -> Result<String, EnvelopeError> {
        let key = Self::derive_key(passphrase)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| EnvelopeError::CryptoError(e.to_string()))?;

        let mut iv_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut iv_bytes);
        let nonce = Nonce::from_slice(&iv_bytes);

        let ciphertext_bytes = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| EnvelopeError::CryptoError(e.to_string()))?;

        let envelope = EncryptedPayloadEnvelope {
            version: Self::SUPPORTED_VERSION,
            algorithm: Self::SUPPORTED_ALGORITHM.to_string(),
            encoding: Self::SUPPORTED_ENCODING.to_string(),
            iv: URL_SAFE_NO_PAD.encode(iv_bytes),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext_bytes),
        };

        serde_json::to_string(&envelope).map_err(EnvelopeError::from)
    }

    /// Decrypts an envelope JSON string back into raw bytes.
    pub fn decrypt(payload_json: &str, passphrase: &str) -> Result<Vec<u8>, EnvelopeError> {
        let key = Self::derive_key(passphrase)?;
        let envelope: EncryptedPayloadEnvelope = serde_json::from_str(payload_json)?;

        if envelope.version != Self::SUPPORTED_VERSION {
            return Err(EnvelopeError::UnsupportedVersion {
                expected: Self::SUPPORTED_VERSION,
                actual: envelope.version,
            });
        }
        if envelope.algorithm != Self::SUPPORTED_ALGORITHM {
            return Err(EnvelopeError::UnsupportedAlgorithm(envelope.algorithm));
        }
        if envelope.encoding != Self::SUPPORTED_ENCODING {
            return Err(EnvelopeError::UnsupportedEncoding(envelope.encoding));
        }

        let iv_bytes = Self::decode_base64_url_safe(&envelope.iv)?;
        if iv_bytes.len() != 12 {
            return Err(EnvelopeError::CryptoError(format!(
                "Invalid IV length: expected 12 bytes, got {}",
                iv_bytes.len()
            )));
        }

        let ciphertext_bytes = Self::decode_base64_url_safe(&envelope.ciphertext)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| EnvelopeError::CryptoError(e.to_string()))?;
        let nonce = Nonce::from_slice(&iv_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext_bytes.as_ref())
            .map_err(|e| EnvelopeError::CryptoError(e.to_string()))?;

        Ok(plaintext)
    }

    /// Decrypts an envelope JSON string into a UTF-8 string.
    pub fn decrypt_text(payload_json: &str, passphrase: &str) -> Result<String, EnvelopeError> {
        let bytes = Self::decrypt(payload_json, passphrase)?;
        String::from_utf8(bytes).map_err(EnvelopeError::from)
    }

    /// Parses a whitespace/newline separated list of IPv4 strings, validating and deduplicating them.
    pub fn parse_plaintext_ips(text: &str) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut result = Vec::new();

        for token in text.split_whitespace() {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                continue;
            }
            if Ipv4Addr::from_str(trimmed).is_ok() {
                let s = trimmed.to_string();
                if seen.insert(s.clone()) {
                    result.push(s);
                }
            }
        }
        result
    }

    /// Encrypts an IPv4 list into an envelope JSON string.
    pub fn encrypt_ip_list(ips: &[&str], passphrase: &str) -> Result<String, EnvelopeError> {
        let text = ips.join("\n");
        Self::encrypt(text.as_bytes(), passphrase)
    }

    /// Decrypts an envelope JSON string and extracts unique valid IPv4 addresses.
    pub fn decrypt_ip_list(payload_json: &str, passphrase: &str) -> Result<Vec<String>, EnvelopeError> {
        let text = Self::decrypt_text(payload_json, passphrase)?;
        let ips = Self::parse_plaintext_ips(&text);
        if ips.is_empty() {
            return Err(EnvelopeError::EmptyIpList);
        }
        Ok(ips)
    }

    fn decode_base64_url_safe(input: &str) -> Result<Vec<u8>, EnvelopeError> {
        let trimmed: String = input.chars().filter(|c| !c.is_whitespace()).collect();
        let unpadded = trimmed.trim_end_matches('=');
        URL_SAFE_NO_PAD
            .decode(unpadded)
            .map_err(|e| EnvelopeError::Base64Error(e.to_string()))
    }
}
