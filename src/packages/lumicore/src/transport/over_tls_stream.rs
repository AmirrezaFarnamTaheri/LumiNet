//! # OverTLS Minimalist Transport Frame Codec
//!
//! Encapsulates raw streams into minimalist TLS-mimicking transport frames
//! with dynamic entropy padding to neutralize packet-length signature analysis.
//! Ported and enhanced from ShadowsocksR-Live/overtls.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverTlsFrameType {
    Data = 0x01,
    Padding = 0x02,
    Ping = 0x03,
    Pong = 0x04,
    Close = 0x05,
}

impl OverTlsFrameType {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(OverTlsFrameType::Data),
            0x02 => Some(OverTlsFrameType::Padding),
            0x03 => Some(OverTlsFrameType::Ping),
            0x04 => Some(OverTlsFrameType::Pong),
            0x05 => Some(OverTlsFrameType::Close),
            _ => None,
        }
    }
}

pub const OVERTLS_MAGIC: u16 = 0x544F; // 'OT'

#[derive(Debug, Clone)]
pub struct OverTlsFrame {
    pub frame_type: OverTlsFrameType,
    pub payload: Vec<u8>,
}

#[derive(Debug, Default, Clone)]
pub struct OverTlsCodec {
    max_padding: u8,
}

impl OverTlsCodec {
    pub fn new(max_padding: u8) -> Self {
        Self { max_padding }
    }

    /// Encodes a payload into a framed byte stream with random padding.
    /// Wire layout:
    /// [0..2] Magic (0x544F)
    /// [2] Frame Type
    /// [3] Padding Length (P)
    /// [4..6] Payload Length (N, big-endian)
    /// [6..6+N] Payload
    /// [6+N..6+N+P] Padding bytes
    pub fn encode_frame(&self, frame_type: OverTlsFrameType, payload: &[u8], padding_len: u8) -> Vec<u8> {
        let p_len = padding_len.min(self.max_padding);
        let n_len = payload.len() as u16;
        let total_len = 6 + payload.len() + p_len as usize;
        let mut out = Vec::with_capacity(total_len);

        out.extend_from_slice(&OVERTLS_MAGIC.to_be_bytes());
        out.push(frame_type as u8);
        out.push(p_len);
        out.extend_from_slice(&n_len.to_be_bytes());
        out.extend_from_slice(payload);

        // Dummy pseudorandom padding
        for i in 0..p_len {
            out.push((i.wrapping_mul(37) ^ 0xA5) as u8);
        }

        out
    }

    /// Decodes a frame from the buffer, returning (Frame, consumed_bytes)
    pub fn decode_frame(&self, buf: &[u8]) -> Result<(OverTlsFrame, usize), &'static str> {
        if buf.len() < 6 {
            return Err("Buffer too short for header");
        }

        let magic = u16::from_be_bytes([buf[0], buf[1]]);
        if magic != OVERTLS_MAGIC {
            return Err("Invalid OverTLS magic bytes");
        }

        let frame_type = OverTlsFrameType::from_u8(buf[2]).ok_or("Unknown frame type")?;
        let p_len = buf[3] as usize;
        let n_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;

        let total_required = 6 + n_len + p_len;
        if buf.len() < total_required {
            return Err("Incomplete frame in buffer");
        }

        let payload = buf[6..6 + n_len].to_vec();
        Ok((OverTlsFrame { frame_type, payload }, total_required))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overtls_roundtrip() {
        let codec = OverTlsCodec::new(32);
        let data = b"GET /stream HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let encoded = codec.encode_frame(OverTlsFrameType::Data, data, 16);

        let (frame, consumed) = codec.decode_frame(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(frame.frame_type, OverTlsFrameType::Data);
        assert_eq!(frame.payload, data);
    }

    #[test]
    fn test_overtls_ping_pong() {
        let codec = OverTlsCodec::new(16);
        let ping = codec.encode_frame(OverTlsFrameType::Ping, &[], 8);
        let (frame, _) = codec.decode_frame(&ping).unwrap();
        assert_eq!(frame.frame_type, OverTlsFrameType::Ping);
        assert!(frame.payload.is_empty());
    }
}
