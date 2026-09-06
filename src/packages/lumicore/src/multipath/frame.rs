//! Multipath Frame Protocol
//!
//! Ported and unified from `XPlex-main` (`internal/mpframe`).
//! Defines the binary wire format exchanged between multipath clients and servers.
//! Header is a fixed 29 bytes:
//!
//! ```text
//! +--------+--------------------+--------------------+--------------------+
//! |  type  |  session ID (16B)  |  seqno (u64 BE)    |  payload len (u32) |
//! |  1 B   |        16 B        |       8 B          |       4 B          |
//! +--------+--------------------+--------------------+--------------------+
//! |                       payload (length B)                              |
//! +-----------------------------------------------------------------------+
//! ```

use std::fmt;

/// Fixed header length in bytes: 1 (type) + 16 (sid) + 8 (seq) + 4 (len) = 29 bytes.
pub const MP_HEADER_LEN: usize = 29;

/// Maximum payload length allowed per frame (2 MiB).
pub const MP_MAX_PAYLOAD: u32 = 2 * 1024 * 1024;

/// Multipath frame types. Wire-stable constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MpFrameType {
    /// Session initiation with destination string payload.
    Hello = 0x01,
    /// Initiation acknowledgment (empty payload = success, non-empty = error message).
    HelloAck = 0x02,
    /// In-order stream data payload.
    Data = 0x03,
    /// Session teardown request.
    Close = 0x04,
    /// Path-level keepalive probe.
    Ping = 0x05,
    /// Keepalive response.
    Pong = 0x06,
}

impl TryFrom<u8> for MpFrameType {
    type Error = MpFrameError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0x01 => Ok(MpFrameType::Hello),
            0x02 => Ok(MpFrameType::HelloAck),
            0x03 => Ok(MpFrameType::Data),
            0x04 => Ok(MpFrameType::Close),
            0x05 => Ok(MpFrameType::Ping),
            0x06 => Ok(MpFrameType::Pong),
            other => Err(MpFrameError::UnknownType(other)),
        }
    }
}

/// Errors occurring during frame encoding or decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MpFrameError {
    BufferTooShort { needed: usize, found: usize },
    UnknownType(u8),
    PayloadTooLarge { max: u32, found: u32 },
    TruncatedPayload { expected: usize, found: usize },
}

impl fmt::Display for MpFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort { needed, found } => {
                write!(f, "buffer too short: needed {} bytes, found {}", needed, found)
            }
            Self::UnknownType(t) => write!(f, "unknown multipath frame type 0x{:02X}", t),
            Self::PayloadTooLarge { max, found } => {
                write!(f, "payload exceeds max {} bytes, found {}", max, found)
            }
            Self::TruncatedPayload { expected, found } => {
                write!(f, "truncated payload: expected {} bytes, found {}", expected, found)
            }
        }
    }
}

impl std::error::Error for MpFrameError {}

/// A binary multipath frame multiplexed across bonded tunnels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpFrame {
    pub frame_type: MpFrameType,
    pub session_id: [u8; 16],
    pub seq: u64,
    pub payload: Vec<u8>,
}

impl MpFrame {
    /// Creates a new multipath frame.
    pub fn new(
        frame_type: MpFrameType,
        session_id: [u8; 16],
        seq: u64,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            frame_type,
            session_id,
            seq,
            payload,
        }
    }

    /// Serializes the frame into binary format.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(MP_HEADER_LEN + self.payload.len());
        buf.push(self.frame_type as u8);
        buf.extend_from_slice(&self.session_id);
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Deserializes a frame from binary bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, MpFrameError> {
        if buf.len() < MP_HEADER_LEN {
            return Err(MpFrameError::BufferTooShort {
                needed: MP_HEADER_LEN,
                found: buf.len(),
            });
        }

        let frame_type = MpFrameType::try_from(buf[0])?;
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&buf[1..17]);

        let seq = u64::from_be_bytes(buf[17..25].try_into().unwrap());
        let payload_len = u32::from_be_bytes(buf[25..29].try_into().unwrap());

        if payload_len > MP_MAX_PAYLOAD {
            return Err(MpFrameError::PayloadTooLarge {
                max: MP_MAX_PAYLOAD,
                found: payload_len,
            });
        }

        let total_expected = MP_HEADER_LEN + payload_len as usize;
        if buf.len() < total_expected {
            return Err(MpFrameError::TruncatedPayload {
                expected: total_expected,
                found: buf.len(),
            });
        }

        let payload = buf[MP_HEADER_LEN..total_expected].to_vec();
        Ok(Self {
            frame_type,
            session_id,
            seq,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpframe_roundtrip() {
        let sid = [0x7A; 16];
        let frame = MpFrame::new(
            MpFrameType::Data,
            sid,
            42,
            b"multipath bonded packet".to_vec(),
        );

        let bytes = frame.encode();
        assert_eq!(bytes.len(), MP_HEADER_LEN + frame.payload.len());

        let decoded = MpFrame::decode(&bytes).expect("decode ok");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_mpframe_unknown_type() {
        let mut bytes = vec![0xFF]; // Invalid type
        bytes.extend_from_slice(&[0u8; 28]);
        assert_eq!(
            MpFrame::decode(&bytes),
            Err(MpFrameError::UnknownType(0xFF))
        );
    }
}
