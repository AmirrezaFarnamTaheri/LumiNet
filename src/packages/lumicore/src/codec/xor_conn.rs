// Clean-room re-implementation of VLESS XorConn — XOR-padded connection obfuscation.
// MIT License.

use thiserror::Error;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during XOR obfuscation.
#[derive(Debug, Error)]
pub enum XorConnError {
    /// Input buffer is too short to contain the XOR header.
    #[error("input too short for XOR header: need ≥{min} bytes, got {got}")]
    BufferTooShort { min: usize, got: usize },

    /// The XOR header magic bytes do not match.
    #[error("invalid XOR header magic: expected {expected:#04x}, got {got:#04x}")]
    InvalidMagic { expected: u8, got: u8 },

    /// CRC-8 checksum mismatch on the XOR header.
    #[error("XOR header CRC mismatch: expected {expected:#04x}, got {got:#04x}")]
    CrcMismatch { expected: u8, got: u8 },

    /// Target destination was all zeros (invalid).
    #[error("target destination is all zeros")]
    InvalidDestination,

    /// Output buffer is too small to hold the obfuscated payload.
    #[error("output buffer too small: need {need} bytes, have {have}")]
    OutputTooSmall { need: usize, have: usize },
}

// ---------------------------------------------------------------------------
// CRC-8
// ---------------------------------------------------------------------------

/// CRC-8 with polynomial 0x07 (the one Xray uses for XorConn headers).
const CRC8_POLY: u8 = 0x07;

/// CRC-8 with initial value 0 and no final XOR. Matches the Xray implementation.
pub fn crc8(data: &[u8]) -> u8 {
    let mut crc = 0u8;
    for &byte in data {
        crc ^= byte;
        for _ in 0..8 {
            crc = if crc & 0x80 != 0 {
                (crc << 1) ^ CRC8_POLY
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// XorConn protocol header.
#[derive(Debug, Clone)]
pub struct XorConnHeader {
    /// The XOR-ed destination address. On the wire this is XORed with `MAGIC`.
    pub dst: [u8; 6],
    /// CRC-8 checksum of the original (un-XORed) header.
    pub crc: u8,
}

impl XorConnHeader {
    /// MAGIC byte used for XOR obfuscation. The first byte of every XorConn
    /// packet on the wire is always `MAGIC ^ 0x09`.
    pub const MAGIC: u8 = 0x09;

    /// Length of the on-wire header in bytes: 1 (magic) + 6 (dst) + 1 (crc) = 8.
    pub const WIRE_LEN: usize = 8;

    /// Build a header from a destination address. `dst` must be exactly 6 bytes
    /// (IPv4 = 4 bytes padded to 6, or IPv6 = first 6 bytes of the 16-byte addr).
    pub fn new(dst: [u8; 6]) -> Result<Self, XorConnError> {
        if dst.iter().all(|&b| b == 0) {
            return Err(XorConnError::InvalidDestination);
        }
        let crc = Self::compute_crc(&dst);
        Ok(Self { dst, crc })
    }

    /// Decode from a wire buffer (at least 8 bytes). Validates magic and CRC.
    pub fn from_wire(buf: &[u8]) -> Result<Self, XorConnError> {
        if buf.len() < Self::WIRE_LEN {
            return Err(XorConnError::BufferTooShort {
                min: Self::WIRE_LEN,
                got: buf.len(),
            });
        }

        // The first byte on the wire is `MAGIC ^ 0x09`, so XOR it back to get 0x09.
        let magic_input = buf[0] ^ Self::MAGIC;
        if magic_input != 0x09 {
            return Err(XorConnError::InvalidMagic {
                expected: 0x09,
                got: magic_input,
            });
        }

        // Decode the 6 destination bytes: wire[1..7] = header.dst ^ MAGIC.
        let mut dst = [0u8; 6];
        for i in 0..6 {
            dst[i] = buf[1 + i] ^ Self::MAGIC;
        }

        // The CRC byte on the wire is also XORed with MAGIC.
        let wire_crc = buf[7] ^ Self::MAGIC;
        let computed_crc = Self::compute_crc(&dst);

        if wire_crc != computed_crc {
            return Err(XorConnError::CrcMismatch {
                expected: computed_crc,
                got: wire_crc,
            });
        }

        Ok(Self { dst, crc: computed_crc })
    }

    /// Encode to a wire buffer. Caller must provide a buffer of at least 8 bytes.
    pub fn to_wire(&self, buf: &mut [u8]) -> Result<usize, XorConnError> {
        if buf.len() < Self::WIRE_LEN {
            return Err(XorConnError::OutputTooSmall {
                need: Self::WIRE_LEN,
                have: buf.len(),
            });
        }

        // Magic: 0x09 XORed with MAGIC → 0x09 ^ 0x09 = 0x00.
        buf[0] = 0x00;

        // Destination: XOR each byte with MAGIC.
        for i in 0..6 {
            buf[1 + i] = self.dst[i] ^ Self::MAGIC;
        }

        // CRC: also XORed with MAGIC on the wire.
        buf[7] = self.crc ^ Self::MAGIC;

        Ok(Self::WIRE_LEN)
    }

    #[inline]
    fn compute_crc(dst: &[u8; 6]) -> u8 {
        crc8(dst)
    }

    /// Extract the IPv4 address from the destination, if it is a valid IPv4
    /// (i.e., the first 2 bytes are 0x00 0x00).
    pub fn try_ipv4(&self) -> Option<[u8; 4]> {
        if self.dst[0] == 0 && self.dst[1] == 0 {
            Some([self.dst[2], self.dst[3], self.dst[4], self.dst[5]])
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// XorConn — the main obfuscator
// ---------------------------------------------------------------------------

/// Configuration for a XorConn session.
#[derive(Debug, Clone)]
pub struct XorConnConfig {
    /// Shared key for additional XOR layer. When empty, no additional XOR is applied.
    pub key: Vec<u8>,
    /// Maximum number of bytes to prepend before the payload (the XorConn header
    /// is always prepended; this adds extra random padding for better obfuscation).
    pub max_padding: usize,
}

impl Default for XorConnConfig {
    fn default() -> Self {
        Self {
            key: Vec::new(),
            max_padding: 0,
        }
    }
}

/// XorConn — VLESS XOR-padded connection obfuscator.
///
/// Wraps a bidirectional stream with the XorConn protocol:
///   1. Client sends an 8-byte header (magic + dst + crc, all XORed with 0x09).
///   2. Server echoes the header back.
///   3. Both sides optionally XOR the payload with the shared key.
///   4. Optional random padding is prepended before each payload frame.
pub struct XorConn {
    cfg: XorConnConfig,
}

impl Default for XorConn {
    fn default() -> Self {
        Self::new(XorConnConfig::default())
    }
}

impl XorConn {
    pub fn new(cfg: XorConnConfig) -> Self {
        Self { cfg }
    }

    /// Wrap a connection by sending the XorConn header. Call this before reading
    /// any data from the connection. `dst` must be exactly 6 bytes.
    pub fn wrap(&self, dst: [u8; 6]) -> Result<Vec<u8>, XorConnError> {
        let header = XorConnHeader::new(dst)?;
        let mut buf = vec![0u8; XorConnHeader::WIRE_LEN + self.cfg.max_padding];
        let header_len = header.to_wire(&mut buf)?;

        // Fill padding area with random bytes (if max_padding > 0).
        if self.cfg.max_padding > 0 {
            let padding_len = rand::random::<usize>() % (self.cfg.max_padding + 1);
            if padding_len > 0 {
                // Shift header to make room for padding.
                buf.copy_within(..header_len, padding_len);
                // The padding bytes are already 0 (vec![0u8; ...]) — XOR them
                // with a random key if configured.
                if !self.cfg.key.is_empty() {
                    for i in 0..padding_len {
                        buf[i] ^= self.cfg.key[i % self.cfg.key.len()];
                    }
                }
            }
        }

        Ok(buf)
    }

    /// Wrap raw payload bytes (not including the XorConn header).
    /// Optionally XORs the payload with the shared key.
    pub fn wrap_payload(&self, payload: &[u8]) -> Vec<u8> {
        if self.cfg.key.is_empty() {
            payload.to_vec()
        } else {
            payload
                .iter()
                .enumerate()
                .map(|(i, &b)| b ^ self.cfg.key[i % self.cfg.key.len()])
                .collect()
        }
    }

    /// Unwrap raw payload bytes (reverse the optional key XOR).
    pub fn unwrap_payload(&self, payload: &[u8]) -> Vec<u8> {
        // XOR is its own inverse.
        self.wrap_payload(payload)
    }

    /// Parse the XorConn header from a buffer. Does not validate the destination
    /// (the caller decides what destinations are acceptable).
    pub fn parse_header(&self, buf: &[u8]) -> Result<XorConnHeader, XorConnError> {
        XorConnHeader::from_wire(buf)
    }

    /// Build a header for a given IPv4 address (4 bytes → padded to 6).
    pub fn build_header_ipv4(&self, ip: [u8; 4], port: u16) -> Result<Vec<u8>, XorConnError> {
        let mut dst = [0u8; 6];
        dst[2..].copy_from_slice(&ip);
        dst[4..].copy_from_slice(&port.to_be_bytes());
        self.wrap(dst)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// XOR a buffer in-place with a repeating key. This is the same operation
/// used on both sides (XOR is symmetric).
pub fn xor_inplace(data: &mut [u8], key: &[u8]) {
    if key.is_empty() {
        return;
    }
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc8_known_values() {
        // CRC-8 of empty input is 0.
        assert_eq!(crc8(&[]), 0x00);
        // CRC-8 of [0x01] with poly 0x07 is 0x07.
        assert_eq!(crc8(&[0x01]), 0x07);
        // CRC-8 of [0x01, 0x02] is deterministic.
        let v = crc8(&[0x01, 0x02]);
        assert!(v != 0); // should not be zero for non-trivial input
    }

    #[test]
    fn test_xor_conn_header_new_rejects_zero_dst() {
        let result = XorConnHeader::new([0u8; 6]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, XorConnError::InvalidDestination));
    }

    #[test]
    fn test_xor_conn_header_round_trip_ipv4() {
        let ip = [8, 8, 8, 8];
        let port = 443u16;
        let mut dst = [0u8; 6];
        dst[2..].copy_from_slice(&ip);
        dst[4..].copy_from_slice(&port.to_be_bytes());

        let header = XorConnHeader::new(dst).unwrap();
        let mut wire = vec![0u8; XorConnHeader::WIRE_LEN];
        header.to_wire(&mut wire).unwrap();

        // The first byte on the wire must be 0x00 (MAGIC ^ MAGIC).
        assert_eq!(wire[0], 0x00);

        // Decode it back.
        let decoded = XorConnHeader::from_wire(&wire).unwrap();
        assert_eq!(decoded.dst, header.dst);
        assert_eq!(decoded.crc, header.crc);
    }

    #[test]
    fn test_xor_conn_header_round_trip_ipv6_prefix() {
        // IPv6 first 6 bytes: fd00::1 → [0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
        let dst = [0xfd, 0x00, 0x00, 0x00, 0x00, 0x01];
        let header = XorConnHeader::new(dst).unwrap();
        let mut wire = vec![0u8; XorConnHeader::WIRE_LEN];
        header.to_wire(&mut wire).unwrap();
        let decoded = XorConnHeader::from_wire(&wire).unwrap();
        assert_eq!(decoded.dst, dst);
    }

    #[test]
    fn test_xor_conn_header_invalid_magic() {
        // Put a non-zero byte at position 0.
        let buf = [0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let err = XorConnHeader::from_wire(&buf).unwrap_err();
        assert!(matches!(err, XorConnError::InvalidMagic { .. }));
    }

    #[test]
    fn test_xor_conn_header_crc_mismatch() {
        // Wire with wrong CRC (byte 7 = 0x00 instead of proper XORed CRC).
        let ip = [1, 1, 1, 1];
        let mut dst = [0u8; 6];
        dst[2..].copy_from_slice(&ip);
        dst[4..].copy_from_slice(&12345u16.to_be_bytes());

        let header = XorConnHeader::new(dst).unwrap();
        let mut wire = vec![0u8; XorConnHeader::WIRE_LEN];
        header.to_wire(&mut wire).unwrap();

        // Corrupt the CRC byte.
        wire[7] ^= 0xFF;

        let err = XorConnHeader::from_wire(&wire).unwrap_err();
        assert!(matches!(err, XorConnError::CrcMismatch { .. }));
    }

    #[test]
    fn test_xor_conn_header_buffer_too_short() {
        let buf = [0x00, 0x00, 0x00, 0x00];
        let err = XorConnHeader::from_wire(&buf).unwrap_err();
        assert!(matches!(
            err,
            XorConnError::BufferTooShort { min: 8, got: 4 }
        ));
    }

    #[test]
    fn test_try_ipv4_valid() {
        let ip = [8, 8, 8, 8];
        let mut dst = [0u8; 6];
        dst[2..].copy_from_slice(&ip);
        let header = XorConnHeader::new(dst).unwrap();
        assert_eq!(header.try_ipv4(), Some([8, 8, 8, 8]));
    }

    #[test]
    fn test_try_ipv4_returns_none_for_ipv6_prefix() {
        // First two bytes non-zero → not a valid IPv4-mapped destination.
        let dst = [0xfd, 0x00, 0x00, 0x00, 0x00, 0x01];
        let header = XorConnHeader::new(dst).unwrap();
        assert!(header.try_ipv4().is_none());
    }

    #[test]
    fn test_xor_conn_wrap_payload_is_symmetric() {
        let cfg = XorConnConfig {
            key: vec![0xAB, 0xCD],
            max_padding: 0,
        };
        let conn = XorConn::new(cfg);
        let payload = b"Hello, XorConn!";

        let wrapped = conn.wrap_payload(payload);
        assert_ne!(wrapped.as_slice(), payload);

        let unwrapped = conn.unwrap_payload(&wrapped);
        assert_eq!(unwrapped, payload);
    }

    #[test]
    fn test_xor_conn_wrap_payload_no_key_is_identity() {
        let cfg = XorConnConfig::default();
        let conn = XorConn::new(cfg);
        let payload = b"plaintext";
        assert_eq!(conn.wrap_payload(payload), payload);
    }

    #[test]
    fn test_xor_inplace() {
        let key = [0x5A];
        let mut data = vec![0x00, 0x5A, 0xB4, 0xEE, 0x3C];
        xor_inplace(&mut data, &key);
        assert_eq!(data, vec![0x5A, 0x00, 0xEE, 0xB4, 0x66]);
        xor_inplace(&mut data, &key); // XOR again → original
        assert_eq!(data, vec![0x00, 0x5A, 0xB4, 0xEE, 0x3C]);
    }

    #[test]
    fn test_xor_inplace_empty_key_is_noop() {
        let mut data = vec![0x01, 0x02, 0x03];
        xor_inplace(&mut data, &[]);
        assert_eq!(data, vec![0x01, 0x02, 0x03]);
    }
}
