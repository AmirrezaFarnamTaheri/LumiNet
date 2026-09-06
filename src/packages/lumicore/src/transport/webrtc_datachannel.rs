//! WebRTC DataChannel Framing & Encapsulation Transport
//!
//! Implements RFC 8831 / RFC 8832 DataChannel wire framing, Payload Protocol Identifiers (PPID),
//! and DataChannel Establishment Protocol (DCEP) message codecs.

use std::fmt;

/// RFC 8831 Payload Protocol Identifiers (PPID) for WebRTC DataChannels.
pub const PPID_DCEP: u32 = 50;
pub const PPID_STRING: u32 = 51;
pub const PPID_BINARY: u32 = 53;
pub const PPID_STRING_EMPTY: u32 = 56;
pub const PPID_BINARY_EMPTY: u32 = 57;

/// RFC 8832 DataChannel Establishment Protocol Message Types.
pub const DCEP_MSG_ACK: u8 = 0x02;
pub const DCEP_MSG_OPEN: u8 = 0x03;

/// RFC 8832 Channel Types.
pub const CHANNEL_TYPE_RELIABLE: u8 = 0x00;
pub const CHANNEL_TYPE_RELIABLE_UNORDERED: u8 = 0x80;
pub const CHANNEL_TYPE_PARTIAL_RELIABLE_REXMIT: u8 = 0x01;
pub const CHANNEL_TYPE_PARTIAL_RELIABLE_REXMIT_UNORDERED: u8 = 0x81;
pub const CHANNEL_TYPE_PARTIAL_RELIABLE_TIMED: u8 = 0x02;
pub const CHANNEL_TYPE_PARTIAL_RELIABLE_TIMED_UNORDERED: u8 = 0x82;

/// A WebRTC DataChannel application or control packet frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataChannelFrame {
    pub ppid: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataChannelError {
    BufferTooShort,
    InvalidDcepHeader,
    PayloadTruncated,
}

impl fmt::Display for DataChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort => write!(f, "buffer too short for datachannel frame"),
            Self::InvalidDcepHeader => write!(f, "invalid DCEP message header"),
            Self::PayloadTruncated => write!(f, "datachannel payload truncated"),
        }
    }
}

impl std::error::Error for DataChannelError {}

impl DataChannelFrame {
    /// Creates a binary data frame.
    pub fn new_binary(payload: impl Into<Vec<u8>>) -> Self {
        let p = payload.into();
        let ppid = if p.is_empty() {
            PPID_BINARY_EMPTY
        } else {
            PPID_BINARY
        };
        Self { ppid, payload: p }
    }

    /// Creates a UTF-8 string data frame.
    pub fn new_string(payload: impl Into<Vec<u8>>) -> Self {
        let p = payload.into();
        let ppid = if p.is_empty() {
            PPID_STRING_EMPTY
        } else {
            PPID_STRING
        };
        Self { ppid, payload: p }
    }

    /// Creates a DCEP Open message frame.
    pub fn new_dcep_open(channel_type: u8, priority: u16, reliability_param: u32, label: &str, protocol: &str) -> Self {
        let label_bytes = label.as_bytes();
        let proto_bytes = protocol.as_bytes();
        let mut payload = Vec::with_capacity(12 + label_bytes.len() + proto_bytes.len());

        payload.push(DCEP_MSG_OPEN);
        payload.push(channel_type);
        payload.extend_from_slice(&priority.to_be_bytes());
        payload.extend_from_slice(&reliability_param.to_be_bytes());
        payload.extend_from_slice(&(label_bytes.len() as u16).to_be_bytes());
        payload.extend_from_slice(&(proto_bytes.len() as u16).to_be_bytes());
        payload.extend_from_slice(label_bytes);
        payload.extend_from_slice(proto_bytes);

        Self {
            ppid: PPID_DCEP,
            payload,
        }
    }

    /// Creates a DCEP Ack message frame.
    pub fn new_dcep_ack() -> Self {
        Self {
            ppid: PPID_DCEP,
            payload: vec![DCEP_MSG_ACK],
        }
    }

    /// Encodes the frame into 4-byte big-endian PPID prefix + payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.payload.len());
        out.extend_from_slice(&self.ppid.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decodes a frame from raw bytes.
    pub fn decode(src: &[u8]) -> Result<Self, DataChannelError> {
        if src.len() < 4 {
            return Err(DataChannelError::BufferTooShort);
        }
        let ppid = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
        let payload = src[4..].to_vec();
        Ok(Self { ppid, payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_frame_roundtrip() {
        let data = b"proxy tunneling through webrtc data channel".to_vec();
        let frame = DataChannelFrame::new_binary(data.clone());
        assert_eq!(frame.ppid, PPID_BINARY);

        let encoded = frame.encode();
        assert_eq!(encoded.len(), 4 + data.len());

        let decoded = DataChannelFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.ppid, PPID_BINARY);
        assert_eq!(decoded.payload, data);
    }

    #[test]
    fn test_empty_frame_ppid() {
        let frame = DataChannelFrame::new_binary(Vec::new());
        assert_eq!(frame.ppid, PPID_BINARY_EMPTY);

        let encoded = frame.encode();
        assert_eq!(encoded.len(), 4);

        let decoded = DataChannelFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.ppid, PPID_BINARY_EMPTY);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn test_dcep_open_and_ack() {
        let open_frame = DataChannelFrame::new_dcep_open(
            CHANNEL_TYPE_RELIABLE,
            100,
            0,
            "control-channel",
            "luminet/1.0",
        );
        assert_eq!(open_frame.ppid, PPID_DCEP);
        assert_eq!(open_frame.payload[0], DCEP_MSG_OPEN);

        let encoded = open_frame.encode();
        let decoded = DataChannelFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.ppid, PPID_DCEP);
        assert_eq!(decoded.payload[0], DCEP_MSG_OPEN);

        let ack = DataChannelFrame::new_dcep_ack();
        assert_eq!(ack.ppid, PPID_DCEP);
        assert_eq!(ack.payload, vec![DCEP_MSG_ACK]);
    }
}
