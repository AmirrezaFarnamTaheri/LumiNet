//! Paqet DPI-Evasion Packet Protocol
//!
//! Implements the packet injection, TCP flag manipulation, and tunnel encapsulation protocol.

use std::fmt;

pub const PAQET_MAGIC: u8 = 0x50; // 'P'
pub const PAQET_VERSION: u8 = 0x01;

pub const TYPE_PING: u8 = 0x01;
pub const TYPE_PONG: u8 = 0x02;
pub const TYPE_TCPF: u8 = 0x03;
pub const TYPE_TCP: u8 = 0x04;
pub const TYPE_UDP: u8 = 0x05;

pub const HEADER_LEN: usize = 5;
pub const MAX_HOST_LEN: usize = 253;
pub const MAX_TCPF_COUNT: usize = 64;
pub const MAX_BODY_LEN: usize = 4096;

pub const B_FIN: u16 = 1 << 0;
pub const B_SYN: u16 = 1 << 1;
pub const B_RST: u16 = 1 << 2;
pub const B_PSH: u16 = 1 << 3;
pub const B_ACK: u16 = 1 << 4;
pub const B_URG: u16 = 1 << 5;
pub const B_ECE: u16 = 1 << 6;
pub const B_CWR: u16 = 1 << 7;
pub const B_NS: u16 = 1 << 8;

/// Individual TCP flag set for crafted evasion bursts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
    pub ns: bool,
}

impl TcpFlags {
    pub fn encode(&self) -> u16 {
        let mut v = 0u16;
        if self.fin { v |= B_FIN; }
        if self.syn { v |= B_SYN; }
        if self.rst { v |= B_RST; }
        if self.psh { v |= B_PSH; }
        if self.ack { v |= B_ACK; }
        if self.urg { v |= B_URG; }
        if self.ece { v |= B_ECE; }
        if self.cwr { v |= B_CWR; }
        if self.ns { v |= B_NS; }
        v
    }

    pub fn decode(v: u16) -> Self {
        Self {
            fin: (v & B_FIN) != 0,
            syn: (v & B_SYN) != 0,
            rst: (v & B_RST) != 0,
            psh: (v & B_PSH) != 0,
            ack: (v & B_ACK) != 0,
            urg: (v & B_URG) != 0,
            ece: (v & B_ECE) != 0,
            cwr: (v & B_CWR) != 0,
            ns: (v & B_NS) != 0,
        }
    }
}

/// Address endpoint target for proxying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaqetAddress {
    pub host: String,
    pub port: u16,
}

/// Message payload container for Paqet protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaqetMessage {
    Ping,
    Pong,
    Tcp(PaqetAddress),
    Udp(PaqetAddress),
    Tcpf(Vec<TcpFlags>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaqetError {
    BufferTooShort,
    InvalidMagic { expected: u8, found: u8 },
    UnsupportedVersion { expected: u8, found: u8 },
    UnknownType(u8),
    HostTooLong(usize),
    TooManyTcpFlags(usize),
    BodyTooLong(usize),
    InvalidString(String),
}

impl fmt::Display for PaqetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort => write!(f, "buffer too short"),
            Self::InvalidMagic { expected, found } => {
                write!(f, "invalid magic 0x{:02X}, expected 0x{:02X}", found, expected)
            }
            Self::UnsupportedVersion { expected, found } => {
                write!(f, "unsupported version {}, expected {}", found, expected)
            }
            Self::UnknownType(t) => write!(f, "unknown message type 0x{:02X}", t),
            Self::HostTooLong(len) => write!(f, "host length {} exceeds maximum {}", len, MAX_HOST_LEN),
            Self::TooManyTcpFlags(count) => write!(f, "TCP flags count {} exceeds maximum {}", count, MAX_TCPF_COUNT),
            Self::BodyTooLong(len) => write!(f, "body length {} exceeds maximum {}", len, MAX_BODY_LEN),
            Self::InvalidString(e) => write!(f, "invalid string encoding: {}", e),
        }
    }
}

impl std::error::Error for PaqetError {}

pub struct PaqetProto;

impl PaqetProto {
    /// Serializes a Paqet message into raw binary wire bytes.
    pub fn encode(msg: &PaqetMessage) -> Result<Vec<u8>, PaqetError> {
        let (msg_type, body) = match msg {
            PaqetMessage::Ping => (TYPE_PING, Vec::new()),
            PaqetMessage::Pong => (TYPE_PONG, Vec::new()),
            PaqetMessage::Tcp(addr) => {
                let host_bytes = addr.host.as_bytes();
                if host_bytes.len() > MAX_HOST_LEN {
                    return Err(PaqetError::HostTooLong(host_bytes.len()));
                }
                let mut b = Vec::with_capacity(1 + host_bytes.len() + 2);
                b.push(host_bytes.len() as u8);
                b.extend_from_slice(host_bytes);
                b.extend_from_slice(&addr.port.to_be_bytes());
                (TYPE_TCP, b)
            }
            PaqetMessage::Udp(addr) => {
                let host_bytes = addr.host.as_bytes();
                if host_bytes.len() > MAX_HOST_LEN {
                    return Err(PaqetError::HostTooLong(host_bytes.len()));
                }
                let mut b = Vec::with_capacity(1 + host_bytes.len() + 2);
                b.push(host_bytes.len() as u8);
                b.extend_from_slice(host_bytes);
                b.extend_from_slice(&addr.port.to_be_bytes());
                (TYPE_UDP, b)
            }
            PaqetMessage::Tcpf(flags) => {
                if flags.len() > MAX_TCPF_COUNT {
                    return Err(PaqetError::TooManyTcpFlags(flags.len()));
                }
                let mut b = Vec::with_capacity(1 + flags.len() * 2);
                b.push(flags.len() as u8);
                for f in flags {
                    b.extend_from_slice(&f.encode().to_be_bytes());
                }
                (TYPE_TCPF, b)
            }
        };

        if body.len() > MAX_BODY_LEN {
            return Err(PaqetError::BodyTooLong(body.len()));
        }

        let mut out = Vec::with_capacity(HEADER_LEN + body.len());
        out.push(PAQET_MAGIC);
        out.push(PAQET_VERSION);
        out.push(msg_type);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Deserializes a Paqet message from raw bytes.
    /// Returns the parsed message and number of bytes consumed.
    pub fn decode(src: &[u8]) -> Result<(PaqetMessage, usize), PaqetError> {
        if src.len() < HEADER_LEN {
            return Err(PaqetError::BufferTooShort);
        }

        if src[0] != PAQET_MAGIC {
            return Err(PaqetError::InvalidMagic {
                expected: PAQET_MAGIC,
                found: src[0],
            });
        }

        if src[1] != PAQET_VERSION {
            return Err(PaqetError::UnsupportedVersion {
                expected: PAQET_VERSION,
                found: src[1],
            });
        }

        let msg_type = src[2];
        let body_len = u16::from_be_bytes([src[3], src[4]]) as usize;
        let total_len = HEADER_LEN + body_len;

        if src.len() < total_len {
            return Err(PaqetError::BufferTooShort);
        }

        let body = &src[HEADER_LEN..total_len];

        let msg = match msg_type {
            TYPE_PING => PaqetMessage::Ping,
            TYPE_PONG => PaqetMessage::Pong,
            TYPE_TCP => {
                if body.is_empty() {
                    return Err(PaqetError::BufferTooShort);
                }
                let host_len = body[0] as usize;
                if body.len() < 1 + host_len + 2 {
                    return Err(PaqetError::BufferTooShort);
                }
                let host = String::from_utf8(body[1..1 + host_len].to_vec())
                    .map_err(|e| PaqetError::InvalidString(e.to_string()))?;
                let port = u16::from_be_bytes([body[1 + host_len], body[2 + host_len]]);
                PaqetMessage::Tcp(PaqetAddress { host, port })
            }
            TYPE_UDP => {
                if body.is_empty() {
                    return Err(PaqetError::BufferTooShort);
                }
                let host_len = body[0] as usize;
                if body.len() < 1 + host_len + 2 {
                    return Err(PaqetError::BufferTooShort);
                }
                let host = String::from_utf8(body[1..1 + host_len].to_vec())
                    .map_err(|e| PaqetError::InvalidString(e.to_string()))?;
                let port = u16::from_be_bytes([body[1 + host_len], body[2 + host_len]]);
                PaqetMessage::Udp(PaqetAddress { host, port })
            }
            TYPE_TCPF => {
                if body.is_empty() {
                    return Err(PaqetError::BufferTooShort);
                }
                let count = body[0] as usize;
                if body.len() < 1 + count * 2 {
                    return Err(PaqetError::BufferTooShort);
                }
                let mut flags = Vec::with_capacity(count);
                for i in 0..count {
                    let offset = 1 + i * 2;
                    let val = u16::from_be_bytes([body[offset], body[offset + 1]]);
                    flags.push(TcpFlags::decode(val));
                }
                PaqetMessage::Tcpf(flags)
            }
            other => return Err(PaqetError::UnknownType(other)),
        };

        Ok((msg, total_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paqet_ping_pong() {
        let ping = PaqetProto::encode(&PaqetMessage::Ping).unwrap();
        assert_eq!(ping, vec![PAQET_MAGIC, PAQET_VERSION, TYPE_PING, 0, 0]);

        let (msg, len) = PaqetProto::decode(&ping).unwrap();
        assert_eq!(len, 5);
        assert_eq!(msg, PaqetMessage::Ping);
    }

    #[test]
    fn test_paqet_tcp_address() {
        let addr = PaqetAddress {
            host: "target.local".into(),
            port: 8443,
        };
        let encoded = PaqetProto::encode(&PaqetMessage::Tcp(addr.clone())).unwrap();
        let (msg, len) = PaqetProto::decode(&encoded).unwrap();
        assert_eq!(len, encoded.len());
        assert_eq!(msg, PaqetMessage::Tcp(addr));
    }

    #[test]
    fn test_paqet_tcp_flags() {
        let flags = vec![
            TcpFlags { syn: true, ..Default::default() },
            TcpFlags { syn: true, ack: true, ..Default::default() },
            TcpFlags { ack: true, psh: true, ..Default::default() },
        ];
        let encoded = PaqetProto::encode(&PaqetMessage::Tcpf(flags.clone())).unwrap();
        let (msg, len) = PaqetProto::decode(&encoded).unwrap();
        assert_eq!(len, encoded.len());
        assert_eq!(msg, PaqetMessage::Tcpf(flags));
    }
}
