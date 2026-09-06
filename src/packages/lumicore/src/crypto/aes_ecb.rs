//! # AES-128-ECB Primitives
//!
//! Provides raw AES-128 Electronic Code Book mode encryption/decryption,
//!
//! Used by legacy Shadowsocks stream cipher key derivation and
//! VMess encryption AES-CFB-128 underlying primitives.
//!
//! # Warning
//! ECB mode is NOT authenticated. Use only for primitive key operations,
//! not for data stream encryption.

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;

const AES128_BLOCK_SIZE: usize = 16;
const AES128_KEY_SIZE: usize = 16;

/// AES-128 ECB cipher wrapper.
pub struct Aes128Ecb {
    cipher: Aes128,
}

impl Aes128Ecb {
    /// Creates a new AES-128-ECB instance from a 16-byte key.
    ///
    /// # Errors
    /// Returns `EcbError::InvalidKey` if the key length is not exactly 16 bytes.
    pub fn new(key: &[u8]) -> Result<Self, EcbError> {
        if key.len() != AES128_KEY_SIZE {
            return Err(EcbError::InvalidKey(key.len()));
        }
        let key_arr = GenericArray::from_slice(key);
        let cipher = Aes128::new(key_arr);
        Ok(Self { cipher })
    }

    /// Encrypts a single 16-byte block in-place.
    ///
    /// # Errors
    /// Returns `EcbError::InvalidBlockSize` if the block length is not exactly 16 bytes.
    pub fn encrypt_block(&self, block: &mut [u8]) -> Result<(), EcbError> {
        if block.len() != AES128_BLOCK_SIZE {
            return Err(EcbError::InvalidBlockSize(block.len()));
        }
        let block_arr = GenericArray::from_mut_slice(block);
        self.cipher.encrypt_block(block_arr);
        Ok(())
    }

    /// Decrypts a single 16-byte block in-place.
    ///
    /// # Errors
    /// Returns `EcbError::InvalidBlockSize` if the block length is not exactly 16 bytes.
    pub fn decrypt_block(&self, block: &mut [u8]) -> Result<(), EcbError> {
        if block.len() != AES128_BLOCK_SIZE {
            return Err(EcbError::InvalidBlockSize(block.len()));
        }
        let block_arr = GenericArray::from_mut_slice(block);
        self.cipher.decrypt_block(block_arr);
        Ok(())
    }

    /// Encrypts multiple blocks of plaintext using ECB mode.
    ///
    /// Input must be a multiple of 16 bytes long.
    pub fn encrypt_blocks(&self, data: &[u8]) -> Result<Vec<u8>, EcbError> {
        if !data.len().is_multiple_of(AES128_BLOCK_SIZE) {
            return Err(EcbError::UnalignedData(data.len()));
        }
        let mut out = data.to_vec();
        for chunk in out.chunks_exact_mut(AES128_BLOCK_SIZE) {
            let block = GenericArray::from_mut_slice(chunk);
            self.cipher.encrypt_block(block);
        }
        Ok(out)
    }

    /// Decrypts multiple blocks of ciphertext using ECB mode.
    ///
    /// Input must be a multiple of 16 bytes long.
    pub fn decrypt_blocks(&self, data: &[u8]) -> Result<Vec<u8>, EcbError> {
        if !data.len().is_multiple_of(AES128_BLOCK_SIZE) {
            return Err(EcbError::UnalignedData(data.len()));
        }
        let mut out = data.to_vec();
        for chunk in out.chunks_exact_mut(AES128_BLOCK_SIZE) {
            let block = GenericArray::from_mut_slice(chunk);
            self.cipher.decrypt_block(block);
        }
        Ok(out)
    }

    /// Adds PKCS#7 padding to plaintext so it aligns to 16-byte boundaries.
    pub fn pad_pkcs7(data: &[u8]) -> Vec<u8> {
        let pad_len = AES128_BLOCK_SIZE - (data.len() % AES128_BLOCK_SIZE);
        let mut padded = data.to_vec();
        padded.extend(std::iter::repeat_n(pad_len as u8, pad_len));
        padded
    }

    /// Strips PKCS#7 padding from decrypted data.
    pub fn unpad_pkcs7(data: &[u8]) -> Result<Vec<u8>, EcbError> {
        if data.is_empty() || !data.len().is_multiple_of(AES128_BLOCK_SIZE) {
            return Err(EcbError::UnalignedData(data.len()));
        }
        let pad_byte = *data.last().unwrap() as usize;
        if pad_byte == 0 || pad_byte > AES128_BLOCK_SIZE {
            return Err(EcbError::InvalidPadding);
        }
        let content_len = data
            .len()
            .checked_sub(pad_byte)
            .ok_or(EcbError::InvalidPadding)?;
        // Verify all padding bytes are correct
        if data[content_len..].iter().any(|&b| b as usize != pad_byte) {
            return Err(EcbError::InvalidPadding);
        }
        Ok(data[..content_len].to_vec())
    }

    /// Encrypts with PKCS#7 padding — convenience wrapper for arbitrary-length input.
    pub fn encrypt_padded(&self, data: &[u8]) -> Result<Vec<u8>, EcbError> {
        let padded = Self::pad_pkcs7(data);
        self.encrypt_blocks(&padded)
    }

    /// Decrypts and strips PKCS#7 padding — convenience wrapper.
    pub fn decrypt_padded(&self, data: &[u8]) -> Result<Vec<u8>, EcbError> {
        let decrypted = self.decrypt_blocks(data)?;
        Self::unpad_pkcs7(&decrypted)
    }
}

/// Errors produced by AES-128-ECB operations.
#[derive(Debug, thiserror::Error)]
pub enum EcbError {
    #[error("invalid key length: expected 16 bytes, got {0}")]
    InvalidKey(usize),
    #[error("invalid block size: expected 16 bytes, got {0}")]
    InvalidBlockSize(usize),
    #[error("data length {0} is not a multiple of 16 bytes")]
    UnalignedData(usize),
    #[error("invalid PKCS#7 padding")]
    InvalidPadding,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x2bu8; 16];
        let ecb = Aes128Ecb::new(&key).unwrap();

        let mut block = [0x6cu8; 16];
        ecb.encrypt_block(&mut block).unwrap();
        ecb.decrypt_block(&mut block).unwrap();
        assert_eq!(block, [0x6cu8; 16]);
    }

    #[test]
    fn test_padded_roundtrip() {
        let key = b"luminet_aes_key!";
        let ecb = Aes128Ecb::new(key).unwrap();
        let plaintext = b"Hello ECB world";
        let ct = ecb.encrypt_padded(plaintext).unwrap();
        let pt = ecb.decrypt_padded(&ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_invalid_key_length() {
        let result = Aes128Ecb::new(b"short");
        assert!(matches!(result, Err(EcbError::InvalidKey(_))));
    }

    #[test]
    fn test_pkcs7_padding() {
        let padded = Aes128Ecb::pad_pkcs7(b"hello");
        assert_eq!(padded.len(), 16);
        assert_eq!(padded[5], 11u8); // 16 - 5 = 11 padding bytes, each == 11

        let unpadded = Aes128Ecb::unpad_pkcs7(&padded).unwrap();
        assert_eq!(unpadded, b"hello");
    }

    #[test]
    fn test_block_aligned_plaintext() {
        let key = b"luminet16bytekey";
        let ecb = Aes128Ecb::new(key).unwrap();
        // 16 bytes exactly — adds a full 16-byte PKCS#7 padding block
        let pt = b"exactly16bytesok";
        let ct = ecb.encrypt_padded(pt).unwrap();
        assert_eq!(ct.len(), 32); // original block + padding block
        let recovered = ecb.decrypt_padded(&ct).unwrap();
        assert_eq!(recovered, pt);
    }
}
