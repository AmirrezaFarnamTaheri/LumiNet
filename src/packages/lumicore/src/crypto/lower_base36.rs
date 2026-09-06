//! # High-Density Lowercase Base36 Codec
//!
//! Encodes arbitrary binary data into DNS-safe lowercase base36 characters `[0-9a-z]`.
//! Packs 7-byte chunks (56 bits) into 11-character base36 words, yielding a 1.57x expansion
//! ratio while adhering to case-insensitive DNS domain and label standards.
//! Conforms to §8 structural rules.

use std::fmt;

pub const LOWER_BASE36_ALPHABET: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";

const ENCODED_CHARS_BY_BYTES: [usize; 8] = [0, 2, 4, 5, 7, 8, 10, 11];
const DECODED_BYTES_BY_CHARS: [usize; 12] = [0, 0, 1, 0, 2, 3, 0, 4, 5, 0, 6, 7];

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum LowerBase36Error {
    InvalidCharacter(char),
    InvalidLength(usize),
    BlockOverflow,
}

impl fmt::Display for LowerBase36Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LowerBase36Error::InvalidCharacter(c) => write!(f, "invalid character in base36: '{}'", c),
            LowerBase36Error::InvalidLength(len) => write!(f, "invalid encoded base36 length: {}", len),
            LowerBase36Error::BlockOverflow => write!(f, "base36 block value exceeded max uint64"),
        }
    }
}

impl std::error::Error for LowerBase36Error {}

/// Calculates the exact encoded string length for `n` bytes of raw input.
pub fn encoded_len(n: usize) -> usize {
    let blocks = n / 7;
    let rem = n % 7;
    blocks * 11 + ENCODED_CHARS_BY_BYTES[rem]
}

/// Encodes raw binary data into lowercase base36 ASCII bytes.
pub fn encode(src: &[u8]) -> Vec<u8> {
    let out_len = encoded_len(src.len());
    let mut dst = vec![0u8; out_len];
    let mut offset = 0;
    let mut remaining = src;

    while remaining.len() >= 7 {
        let val: u64 = ((remaining[0] as u64) << 48)
            | ((remaining[1] as u64) << 40)
            | ((remaining[2] as u64) << 32)
            | ((remaining[3] as u64) << 24)
            | ((remaining[4] as u64) << 16)
            | ((remaining[5] as u64) << 8)
            | (remaining[6] as u64);

        write_base36_block(&mut dst[offset..offset + 11], val, 11);
        offset += 11;
        remaining = &remaining[7..];
    }

    if !remaining.is_empty() {
        let mut val: u64 = 0;
        for &b in remaining {
            val = (val << 8) | (b as u64);
        }
        let count = ENCODED_CHARS_BY_BYTES[remaining.len()];
        write_base36_block(&mut dst[offset..offset + count], val, count);
    }

    dst
}

/// Encodes raw binary data into a lowercase base36 String.
pub fn encode_to_string(src: &[u8]) -> String {
    let bytes = encode(src);
    // SAFETY: Output is purely derived from LOWER_BASE36_ALPHABET which is valid ASCII.
    unsafe { String::from_utf8_unchecked(bytes) }
}

fn write_base36_block(dst: &mut [u8], mut val: u64, count: usize) {
    for i in (0..count).rev() {
        dst[i] = LOWER_BASE36_ALPHABET[(val % 36) as usize];
        val /= 36;
    }
}

/// Decodes lowercase base36 ASCII bytes back into original raw binary.
pub fn decode(src: &[u8]) -> Result<Vec<u8>, LowerBase36Error> {
    if src.is_empty() {
        return Ok(Vec::new());
    }

    let full_blocks = src.len() / 11;
    let rem_chars = src.len() % 11;
    if rem_chars >= 12 || (rem_chars > 0 && DECODED_BYTES_BY_CHARS[rem_chars] == 0) {
        return Err(LowerBase36Error::InvalidLength(src.len()));
    }

    let total_bytes = full_blocks * 7 + DECODED_BYTES_BY_CHARS[rem_chars];
    let mut dst = Vec::with_capacity(total_bytes);

    let mut offset = 0;
    for _ in 0..full_blocks {
        let block = &src[offset..offset + 11];
        let val = parse_base36_block(block)?;
        for shift in (0..7).rev() {
            dst.push(((val >> (shift * 8)) & 0xFF) as u8);
        }
        offset += 11;
    }

    if rem_chars > 0 {
        let block = &src[offset..offset + rem_chars];
        let val = parse_base36_block(block)?;
        let expected_bytes = DECODED_BYTES_BY_CHARS[rem_chars];
        for shift in (0..expected_bytes).rev() {
            dst.push(((val >> (shift * 8)) & 0xFF) as u8);
        }
    }

    Ok(dst)
}

fn parse_base36_block(block: &[u8]) -> Result<u64, LowerBase36Error> {
    let mut val: u64 = 0;
    for &b in block {
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as u64,
            b'a'..=b'z' => (b - b'a' + 10) as u64,
            b'A'..=b'Z' => (b - b'A' + 10) as u64, // case-insensitive tolerant
            other => return Err(LowerBase36Error::InvalidCharacter(other as char)),
        };

        val = val
            .checked_mul(36)
            .and_then(|v| v.checked_add(digit))
            .ok_or(LowerBase36Error::BlockOverflow)?;
    }
    Ok(val)
}
