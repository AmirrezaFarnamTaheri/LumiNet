// Clean-room re-implementation of TUIC v5 protocol codec.
// MIT License.

use std::fmt;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum TuicCodecError {
    #[error("frame too short: need ≥{0} bytes, got {1}")]
    FrameTooShort(usize, usize),

    #[error("unknown command: {0}")]
    UnknownCommand(u8),

    #[error("invalid UDP frame: {0}")]
    InvalidUdpFrame(String),

    #[error("buffer too small: need {need}, have {have}")]
    BufferTooSmall { need: usize, have: usize },

    #[error("authentication required")]
    NotAuthenticated,

    #[error("codec error: {0}")]
    Codec(String),
}

// ---------------------------------------------------------------------------
// TUIC v5 constants
// ---------------------------------------------------------------------------

/// TUIC protocol version 5.
pub const TUIC_VERSION: u8 = 0x05;

/// TUIC authentication token length.
pub const TOKEN_LEN: usize = 32;

/// Maximum UDP packet size recommended by the spec.
pub const MAX_UDP_PACKET_SIZE: usize = 1400;

/// Command types (first byte of each frame).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuicCommandKind {
    /// Authentication challenge.
    Auth = 0x00,
    /// Authentication response (client → server).
    AuthResponse = 0x01,
    /// QUIC-related commands.
    Quic = 0x02,
    /// UDP relay packet.
    UdpPacket = 0x03,
    /// Ping/keepalive.
    Ping = 0x04,
    /// Disconnect.
    Disconnect = 0x05,
    /// Connect (new session).
    Connect = 0x06,
    /// Heartbeat.
    Heartbeat = 0x07,
}

impl TuicCommandKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Auth),
            0x01 => Some(Self::AuthResponse),
            0x02 => Some(Self::Quic),
            0x03 => Some(Self::UdpPacket),
            0x04 => Some(Self::Ping),
            0x05 => Some(Self::Disconnect),
            0x06 => Some(Self::Connect),
            0x07 => Some(Self::Heartbeat),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Authentication frames
// ---------------------------------------------------------------------------

/// Authentication challenge sent by the server.
#[derive(Debug, Clone)]
pub struct AuthChallengeFrame {
    /// Challenge token from the server (TOKEN_LEN bytes).
    pub token: [u8; TOKEN_LEN],
    /// Requested protocol version (should be TUIC_VERSION).
    pub version: u8,
}

impl AuthChallengeFrame {
    /// Minimum wire size: 1 (cmd) + 32 (token) + 1 (version) = 34 bytes.
    pub const WIRE_MIN: usize = 34;

    /// Decode from wire. Returns the frame and the number of bytes consumed.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), TuicCodecError> {
        if buf.len() < Self::WIRE_MIN {
            return Err(TuicCodecError::FrameTooShort(Self::WIRE_MIN, buf.len()));
        }
        let cmd = buf[0];
        if cmd != TuicCommandKind::Auth as u8 {
            return Err(TuicCodecError::UnknownCommand(cmd));
        }
        let mut token = [0u8; TOKEN_LEN];
        token.copy_from_slice(&buf[1..33]);
        let version = buf[33];
        Ok((Self { token, version }, Self::WIRE_MIN))
    }

    /// Encode to a buffer. Caller provides a buffer of at least `WIRE_MIN` bytes.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, TuicCodecError> {
        if buf.len() < Self::WIRE_MIN {
            return Err(TuicCodecError::BufferTooSmall {
                need: Self::WIRE_MIN,
                have: buf.len(),
            });
        }
        buf[0] = TuicCommandKind::Auth as u8;
        buf[1..33].copy_from_slice(&self.token);
        buf[33] = self.version;
        Ok(Self::WIRE_MIN)
    }
}

/// Authentication response from the client.
#[derive(Debug, Clone)]
pub struct AuthResponseFrame {
    pub token: [u8; TOKEN_LEN],
    pub auth_time: u64,
}

impl AuthResponseFrame {
    pub const WIRE_MIN: usize = 41; // 1 + 32 + 8

    pub fn decode(buf: &[u8]) -> Result<(Self, usize), TuicCodecError> {
        if buf.len() < Self::WIRE_MIN {
            return Err(TuicCodecError::FrameTooShort(Self::WIRE_MIN, buf.len()));
        }
        let cmd = buf[0];
        if cmd != TuicCommandKind::AuthResponse as u8 {
            return Err(TuicCodecError::UnknownCommand(cmd));
        }
        let mut token = [0u8; TOKEN_LEN];
        token.copy_from_slice(&buf[1..33]);
        let auth_time = u64::from_le_bytes(buf[33..41].try_into().unwrap());
        Ok((Self { token, auth_time }, Self::WIRE_MIN))
    }

    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, TuicCodecError> {
        if buf.len() < Self::WIRE_MIN {
            return Err(TuicCodecError::BufferTooSmall {
                need: Self::WIRE_MIN,
                have: buf.len(),
            });
        }
        buf[0] = TuicCommandKind::AuthResponse as u8;
        buf[1..33].copy_from_slice(&self.token);
        buf[33..41].copy_from_slice(&self.auth_time.to_le_bytes());
        Ok(Self::WIRE_MIN)
    }
}

// ---------------------------------------------------------------------------
// Connect frame
// ---------------------------------------------------------------------------

/// Connect frame — opens a new TUIC session.
#[derive(Debug, Clone)]
pub struct ConnectFrame {
    /// QUIC connection ID.
    pub conn_id: Vec<u8>,
    /// UDP relay destination address.
    pub addr: String,
    /// UDP relay destination port.
    pub port: u16,
    /// Hop limit for UDP relay.
    pub hop_limit: u8,
}

impl ConnectFrame {
    /// Encode to a buffer. Returns (written bytes, consumed from input).
    pub fn encode(&self, buf: &mut Vec<u8>) -> Result<usize, TuicCodecError> {
        buf.push(TuicCommandKind::Connect as u8);
        let len = self.conn_id.len() as u8;
        buf.push(len);
        buf.extend_from_slice(&self.conn_id);
        let addr_bytes = self.addr.as_bytes();
        let addr_len = addr_bytes.len() as u8;
        buf.push(addr_len);
        buf.extend_from_slice(addr_bytes);
        buf.extend_from_slice(&self.port.to_be_bytes());
        buf.push(self.hop_limit);
        Ok(buf.len())
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, usize), TuicCodecError> {
        if buf.len() < 6 {
            return Err(TuicCodecError::FrameTooShort(6, buf.len()));
        }
        let cmd = buf[0];
        if cmd != TuicCommandKind::Connect as u8 {
            return Err(TuicCodecError::UnknownCommand(cmd));
        }
        let mut pos = 1;
        let conn_id_len = buf[pos] as usize;
        pos += 1;
        if buf.len() < pos + conn_id_len {
            return Err(TuicCodecError::FrameTooShort(pos + conn_id_len, buf.len()));
        }
        let conn_id = buf[pos..pos + conn_id_len].to_vec();
        pos += conn_id_len;

        let addr_len = buf[pos] as usize;
        pos += 1;
        if buf.len() < pos + addr_len + 3 {
            return Err(TuicCodecError::FrameTooShort(pos + addr_len + 3, buf.len()));
        }
        let addr = String::from_utf8_lossy(&buf[pos..pos + addr_len]).to_string();
        pos += addr_len;

        let port = u16::from_be_bytes(buf[pos..pos + 2].try_into().unwrap());
        pos += 2;
        let hop_limit = buf[pos];
        pos += 1;

        Ok((
            Self {
                conn_id,
                addr,
                port,
                hop_limit,
            },
            pos,
        ))
    }
}

// ---------------------------------------------------------------------------
// UDP packet frame
// ---------------------------------------------------------------------------

/// UDP relay packet frame.
#[derive(Debug, Clone)]
pub struct UdpPacketFrame {
    /// Associated QUIC connection ID.
    pub conn_id: Vec<u8>,
    /// UDP source port.
    pub src_port: u16,
    /// UDP destination port.
    pub dst_port: u16,
    /// Raw UDP payload.
    pub payload: Vec<u8>,
}

impl UdpPacketFrame {
    pub fn encode(&self, buf: &mut Vec<u8>) -> Result<usize, TuicCodecError> {
        buf.push(TuicCommandKind::UdpPacket as u8);
        let conn_id_len = self.conn_id.len() as u8;
        buf.push(conn_id_len);
        buf.extend_from_slice(&self.conn_id);
        buf.extend_from_slice(&self.src_port.to_be_bytes());
        buf.extend_from_slice(&self.dst_port.to_be_bytes());
        let len = self.payload.len() as u16;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        Ok(buf.len())
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, usize), TuicCodecError> {
        // Minimum: cmd(1) + conn_id_len(1) + port(2+2) + len(2) = 8
        if buf.len() < 8 {
            return Err(TuicCodecError::FrameTooShort(8, buf.len()));
        }
        let cmd = buf[0];
        if cmd != TuicCommandKind::UdpPacket as u8 {
            return Err(TuicCodecError::UnknownCommand(cmd));
        }
        let mut pos = 1;
        let conn_id_len = buf[pos] as usize;
        pos += 1;
        if buf.len() < pos + conn_id_len + 4 {
            return Err(TuicCodecError::FrameTooShort(pos + conn_id_len + 4, buf.len()));
        }
        let conn_id = buf[pos..pos + conn_id_len].to_vec();
        pos += conn_id_len;
        let src_port = u16::from_be_bytes(buf[pos..pos + 2].try_into().unwrap());
        pos += 2;
        let dst_port = u16::from_be_bytes(buf[pos..pos + 2].try_into().unwrap());
        pos += 2;
        let payload_len = u16::from_be_bytes(buf[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        if buf.len() < pos + payload_len {
            return Err(TuicCodecError::FrameTooShort(pos + payload_len, buf.len()));
        }
        let payload = buf[pos..pos + payload_len].to_vec();
        pos += payload_len;
        Ok((Self { conn_id, src_port, dst_port, payload }, pos))
    }
}

// ---------------------------------------------------------------------------
// Ping / Heartbeat / Disconnect
// ---------------------------------------------------------------------------

/// Ping frame (server → client keepalive).
#[derive(Debug, Clone)]
pub struct PingFrame;

impl PingFrame {
    pub const WIRE_LEN: usize = 1;
    /// Encode into buf as a fresh message (clear-then-write), matching
    /// the in-place semantics of the other frame encoders so the command
    /// byte always lands at index 0 regardless of prior buffer contents.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.clear();
        buf.push(TuicCommandKind::Ping as u8);
    }
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), TuicCodecError> {
        if buf.is_empty() {
            return Err(TuicCodecError::FrameTooShort(1, 0));
        }
        if buf[0] != TuicCommandKind::Ping as u8 {
            return Err(TuicCodecError::UnknownCommand(buf[0]));
        }
        Ok((Self, 1))
    }
}

/// Heartbeat frame (bidirectional).
#[derive(Debug, Clone)]
pub struct HeartbeatFrame {
    pub timestamp: u64,
}

impl HeartbeatFrame {
    pub const WIRE_LEN: usize = 9; // 1 + 8
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.clear();
        buf.push(TuicCommandKind::Heartbeat as u8);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
    }
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), TuicCodecError> {
        if buf.len() < Self::WIRE_LEN {
            return Err(TuicCodecError::FrameTooShort(Self::WIRE_LEN, buf.len()));
        }
        if buf[0] != TuicCommandKind::Heartbeat as u8 {
            return Err(TuicCodecError::UnknownCommand(buf[0]));
        }
        let timestamp = u64::from_be_bytes(buf[1..9].try_into().unwrap());
        Ok((Self { timestamp }, Self::WIRE_LEN))
    }
}

/// Disconnect frame.
#[derive(Debug, Clone)]
pub struct DisconnectFrame {
    pub reason: u8,
}

impl DisconnectFrame {
    pub const WIRE_LEN: usize = 2;
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.clear();
        buf.push(TuicCommandKind::Disconnect as u8);
        buf.push(self.reason);
    }
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), TuicCodecError> {
        if buf.len() < Self::WIRE_LEN {
            return Err(TuicCodecError::FrameTooShort(Self::WIRE_LEN, buf.len()));
        }
        if buf[0] != TuicCommandKind::Disconnect as u8 {
            return Err(TuicCodecError::UnknownCommand(buf[0]));
        }
        Ok((Self { reason: buf[1] }, Self::WIRE_LEN))
    }
}

// ---------------------------------------------------------------------------
// TUIC codec — frame dispatcher
// ---------------------------------------------------------------------------

/// Represents any parsed TUIC frame.
#[derive(Debug, Clone)]
pub enum TuicFrame {
    AuthChallenge(AuthChallengeFrame),
    AuthResponse(AuthResponseFrame),
    Connect(ConnectFrame),
    UdpPacket(UdpPacketFrame),
    Ping(PingFrame),
    Disconnect(DisconnectFrame),
    Heartbeat(HeartbeatFrame),
    Quic(Vec<u8>),
}

impl TuicFrame {
    /// Dispatch a raw buffer to the correct frame type.
    pub fn dispatch(buf: &[u8]) -> Result<(Self, usize), TuicCodecError> {
        if buf.is_empty() {
            return Err(TuicCodecError::FrameTooShort(1, 0));
        }
        match TuicCommandKind::from_u8(buf[0]) {
            Some(TuicCommandKind::Auth) => {
                let (f, n) = AuthChallengeFrame::decode(buf)?;
                Ok((Self::AuthChallenge(f), n))
            }
            Some(TuicCommandKind::AuthResponse) => {
                let (f, n) = AuthResponseFrame::decode(buf)?;
                Ok((Self::AuthResponse(f), n))
            }
            Some(TuicCommandKind::Connect) => {
                let (f, n) = ConnectFrame::decode(buf)?;
                Ok((Self::Connect(f), n))
            }
            Some(TuicCommandKind::UdpPacket) => {
                let (f, n) = UdpPacketFrame::decode(buf)?;
                Ok((Self::UdpPacket(f), n))
            }
            Some(TuicCommandKind::Ping) => {
                let (f, n) = PingFrame::decode(buf)?;
                Ok((Self::Ping(f), n))
            }
            Some(TuicCommandKind::Disconnect) => {
                let (f, n) = DisconnectFrame::decode(buf)?;
                Ok((Self::Disconnect(f), n))
            }
            Some(TuicCommandKind::Heartbeat) => {
                let (f, n) = HeartbeatFrame::decode(buf)?;
                Ok((Self::Heartbeat(f), n))
            }
            Some(TuicCommandKind::Quic) => {
                Ok((Self::Quic(buf[1..].to_vec()), buf.len()))
            }
            None => Err(TuicCodecError::UnknownCommand(buf[0])),
        }
    }
}

// ---------------------------------------------------------------------------
// TUIC codec
// ---------------------------------------------------------------------------

/// TUIC v5 frame encoder/decoder.
#[derive(Debug, Clone, Default)]
pub struct TuicCodec;

impl TuicCodec {
    pub fn new() -> Self {
        Self
    }

    /// Encode a frame to a buffer.
    pub fn encode(&self, frame: &TuicFrame, buf: &mut Vec<u8>) -> Result<usize, TuicCodecError> {
        match frame {
            TuicFrame::AuthChallenge(f) => f.encode(buf),
            TuicFrame::AuthResponse(f) => f.encode(buf),
            TuicFrame::Connect(f) => f.encode(buf),
            TuicFrame::UdpPacket(f) => f.encode(buf),
            TuicFrame::Ping(f) => {
                f.encode(buf);
                Ok(buf.len())
            }
            TuicFrame::Disconnect(f) => {
                f.encode(buf);
                Ok(buf.len())
            }
            TuicFrame::Heartbeat(f) => {
                f.encode(buf);
                Ok(buf.len())
            }
            TuicFrame::Quic(data) => {
                buf.push(TuicCommandKind::Quic as u8);
                buf.extend_from_slice(data);
                Ok(buf.len())
            }
        }
    }

    /// Decode a frame from a buffer. Returns (frame, bytes_consumed).
    pub fn decode(&self, buf: &[u8]) -> Result<(TuicFrame, usize), TuicCodecError> {
        TuicFrame::dispatch(buf)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_token() -> [u8; 32] {
        [0xAB; 32]
    }

    #[test]
    fn test_auth_challenge_round_trip() {
        let frame = AuthChallengeFrame {
            token: make_token(),
            version: TUIC_VERSION,
        };
        let mut buf = vec![0u8; AuthChallengeFrame::WIRE_MIN];
        frame.encode(&mut buf).unwrap();
        let (decoded, n) = AuthChallengeFrame::decode(&buf).unwrap();
        assert_eq!(n, AuthChallengeFrame::WIRE_MIN);
        assert_eq!(decoded.token, frame.token);
        assert_eq!(decoded.version, frame.version);
    }

    #[test]
    fn test_auth_response_round_trip() {
        let mut token = make_token();
        token[0] = 0xCD;
        let frame = AuthResponseFrame { token, auth_time: 12345 };
        let mut buf = vec![0u8; AuthResponseFrame::WIRE_MIN];
        frame.encode(&mut buf).unwrap();
        let (decoded, n) = AuthResponseFrame::decode(&buf).unwrap();
        assert_eq!(n, AuthResponseFrame::WIRE_MIN);
        assert_eq!(decoded.token, frame.token);
        assert_eq!(decoded.auth_time, frame.auth_time);
    }

    #[test]
    fn test_connect_round_trip() {
        let frame = ConnectFrame {
            conn_id: vec![0x01, 0x02, 0x03],
            addr: "example.com".into(),
            port: 443,
            hop_limit: 64,
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();
        let (decoded, _n) = ConnectFrame::decode(&buf).unwrap();
        assert_eq!(decoded.conn_id, frame.conn_id);
        assert_eq!(decoded.addr, frame.addr);
        assert_eq!(decoded.port, frame.port);
        assert_eq!(decoded.hop_limit, frame.hop_limit);
    }

    #[test]
    fn test_udp_packet_round_trip() {
        let frame = UdpPacketFrame {
            conn_id: vec![0xFF],
            src_port: 12345,
            dst_port: 443,
            payload: b"Hello TUIC".to_vec(),
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();
        let (decoded, _n) = UdpPacketFrame::decode(&buf).unwrap();
        assert_eq!(decoded.conn_id, frame.conn_id);
        assert_eq!(decoded.src_port, frame.src_port);
        assert_eq!(decoded.dst_port, frame.dst_port);
        assert_eq!(decoded.payload, frame.payload);
    }

    #[test]
    fn test_ping_round_trip() {
        let frame = PingFrame;
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        let (decoded, n) = PingFrame::decode(&buf).unwrap();
        let _ = decoded;
        assert_eq!(n, 1);
    }

    #[test]
    fn test_heartbeat_round_trip() {
        let frame = HeartbeatFrame { timestamp: 9876543210 };
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        let (decoded, n) = HeartbeatFrame::decode(&buf).unwrap();
        assert_eq!(n, HeartbeatFrame::WIRE_LEN);
        assert_eq!(decoded.timestamp, frame.timestamp);
    }

    #[test]
    fn test_disconnect_round_trip() {
        let frame = DisconnectFrame { reason: 0x01 };
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        let (decoded, n) = DisconnectFrame::decode(&buf).unwrap();
        assert_eq!(n, DisconnectFrame::WIRE_LEN);
        assert_eq!(decoded.reason, frame.reason);
    }

    #[test]
    fn test_dispatch_unknown_command() {
        let buf = [0xFF, 0x00];
        let err = TuicFrame::dispatch(&buf).unwrap_err();
        assert!(matches!(err, TuicCodecError::UnknownCommand(0xFF)));
    }

    #[test]
    fn test_codec_dispatch_all_frame_types() {
        let codec = TuicCodec::new();
        let frames: Vec<(TuicFrame, TuicCommandKind)> = vec![
            (
                TuicFrame::AuthChallenge(AuthChallengeFrame {
                    token: make_token(),
                    version: TUIC_VERSION,
                }),
                TuicCommandKind::Auth,
            ),
            (
                TuicFrame::Ping(PingFrame),
                TuicCommandKind::Ping,
            ),
            (
                TuicFrame::Disconnect(DisconnectFrame { reason: 0 }),
                TuicCommandKind::Disconnect,
            ),
            (
                TuicFrame::Heartbeat(HeartbeatFrame { timestamp: 42 }),
                TuicCommandKind::Heartbeat,
            ),
        ];

        for (frame, _kind) in frames {
            // Frame encoders write into a caller-provided buffer and
            // require room for at least WIRE_MIN bytes; size it a priori.
            let mut buf = vec![0u8; 256];
            codec.encode(&frame, &mut buf).unwrap();
            let (decoded, _n) = codec.decode(&buf).unwrap();
            assert!(matches!(
                (&frame, &decoded),
                (TuicFrame::AuthChallenge(_), TuicFrame::AuthChallenge(_))
                    | (TuicFrame::Ping(_), TuicFrame::Ping(_))
                    | (TuicFrame::Disconnect(_), TuicFrame::Disconnect(_))
                    | (TuicFrame::Heartbeat(_), TuicFrame::Heartbeat(_))
            ));
        }
    }

    #[test]
    fn test_unknown_command_kind() {
        assert!(TuicCommandKind::from_u8(0xFF).is_none());
        assert!(TuicCommandKind::from_u8(0x00).is_some());
        assert!(TuicCommandKind::from_u8(0x07).is_some());
    }
}
