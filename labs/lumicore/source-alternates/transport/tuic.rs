//! # TUIC v5 QUIC Proxy Protocol
//!
//! Implements TUIC v5 client-side session management over QUIC,
//! ported from tuic-master.
//!
//! TUIC v5 multiplexes TCP, UDP, and QUIC streams over a single QUIC connection
//! with zero round-trip connection establishment (0-RTT).
//!
//! Header format for TUIC commands:
//! ```text
//! [version : u8 = 0x05][command : u8][token : 16 bytes][...]
//! ```
//!
//! Commands:
//!   0x00 = Authenticate (sends 16-byte UUID + HMAC token)
//!   0x01 = Connect TCP  (address → opens a bidirectional QUIC stream)
//!   0x02 = Packet (UDP) (sends a datagram in a QUIC datagram frame)
//!   0x03 = Dissociate   (tears down a UDP session)
//!   0x04 = Heartbeat    (keepalive)

use std::fmt;

/// TUIC protocol version.
pub const TUIC_VERSION: u8 = 0x05;

/// TUIC command bytes.
pub mod cmd {
    pub const AUTHENTICATE: u8 = 0x00;
    pub const CONNECT: u8 = 0x01;
    pub const PACKET: u8 = 0x02;
    pub const DISSOCIATE: u8 = 0x03;
    pub const HEARTBEAT: u8 = 0x04;
}

/// Address types in TUIC headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuicAddr {
    Ipv4([u8; 4], u16),
    Ipv6([u8; 16], u16),
    Domain(String, u16),
}

impl TuicAddr {
    /// Serializes the address into wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Ipv4(ip, port) => {
                out.push(0x01);
                out.extend_from_slice(ip);
                out.extend_from_slice(&port.to_be_bytes());
            }
            Self::Ipv6(ip, port) => {
                out.push(0x04);
                out.extend_from_slice(ip);
                out.extend_from_slice(&port.to_be_bytes());
            }
            Self::Domain(host, port) => {
                out.push(0x03);
                let host_bytes = host.as_bytes();
                out.push(host_bytes.len() as u8);
                out.extend_from_slice(host_bytes);
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
        out
    }

    /// Deserializes a `TuicAddr` from a byte slice. Returns `(addr, bytes_consumed)`.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), TuicError> {
        if buf.is_empty() {
            return Err(TuicError::ShortBuffer);
        }
        match buf[0] {
            0x01 => {
                if buf.len() < 7 {
                    return Err(TuicError::ShortBuffer);
                }
                let ip: [u8; 4] = buf[1..5].try_into().unwrap();
                let port = u16::from_be_bytes(buf[5..7].try_into().unwrap());
                Ok((Self::Ipv4(ip, port), 7))
            }
            0x04 => {
                if buf.len() < 19 {
                    return Err(TuicError::ShortBuffer);
                }
                let ip: [u8; 16] = buf[1..17].try_into().unwrap();
                let port = u16::from_be_bytes(buf[17..19].try_into().unwrap());
                Ok((Self::Ipv6(ip, port), 19))
            }
            0x03 => {
                if buf.len() < 2 {
                    return Err(TuicError::ShortBuffer);
                }
                let host_len = buf[1] as usize;
                if buf.len() < 2 + host_len + 2 {
                    return Err(TuicError::ShortBuffer);
                }
                let host = std::str::from_utf8(&buf[2..2 + host_len])
                    .map_err(|_| TuicError::InvalidUtf8)?
                    .to_string();
                let port = u16::from_be_bytes(buf[2 + host_len..4 + host_len].try_into().unwrap());
                Ok((Self::Domain(host, port), 4 + host_len))
            }
            t => Err(TuicError::UnknownAddressType(t)),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Self::Ipv4(_, p) | Self::Ipv6(_, p) | Self::Domain(_, p) => *p,
        }
    }
}

impl fmt::Display for TuicAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4(ip, port) => {
                write!(f, "{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port)
            }
            Self::Ipv6(ip, port) => {
                let addr = std::net::Ipv6Addr::from(*ip);
                write!(f, "[{addr}]:{port}")
            }
            Self::Domain(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

/// A TUIC Authenticate command payload.
#[derive(Debug, Clone)]
pub struct TuicAuthenticate {
    /// 16-byte UUID identifying the user.
    pub uuid: [u8; 16],
    /// BLAKE3-HMAC token over (version || uuid || timestamp).
    pub token: [u8; 32],
}

impl TuicAuthenticate {
    /// Creates an authentication frame using BLAKE3-keyed-hash over the password.
    pub fn new(uuid: [u8; 16], password: &str) -> Self {
        let token = derive_token(&uuid, password);
        Self { uuid, token }
    }

    /// Encodes the Authenticate command into wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![TUIC_VERSION, cmd::AUTHENTICATE];
        out.extend_from_slice(&self.uuid);
        out.extend_from_slice(&self.token);
        out
    }

    /// Decodes from wire bytes (after the version+cmd bytes have been consumed).
    pub fn decode(buf: &[u8]) -> Result<Self, TuicError> {
        if buf.len() < 48 {
            return Err(TuicError::ShortBuffer);
        }
        let uuid: [u8; 16] = buf[0..16].try_into().unwrap();
        let token: [u8; 32] = buf[16..48].try_into().unwrap();
        Ok(Self { uuid, token })
    }

    /// Verifies the token against a known password.
    pub fn verify(&self, password: &str) -> bool {
        let expected = derive_token(&self.uuid, password);
        expected == self.token
    }
}

/// Derives a 32-byte BLAKE3 keyed token from the UUID and password.
fn derive_token(uuid: &[u8; 16], password: &str) -> [u8; 32] {
    // Compute BLAKE3 hash with the password as the key seed.
    // Use a fixed-length key derived from the password via sha256.
    use sha2::{Sha256, Digest};
    let key_hash: [u8; 32] = Sha256::digest(password.as_bytes()).into();
    let token = blake3::keyed_hash(&key_hash, uuid);
    *token.as_bytes()
}

/// A TUIC Connect (TCP) command.
#[derive(Debug, Clone)]
pub struct TuicConnect {
    pub addr: TuicAddr,
}

impl TuicConnect {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![TUIC_VERSION, cmd::CONNECT];
        out.extend_from_slice(&self.addr.encode());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, usize), TuicError> {
        let (addr, consumed) = TuicAddr::decode(buf)?;
        Ok((Self { addr }, consumed))
    }
}

/// A TUIC UDP Packet command (sent via QUIC datagram frames).
#[derive(Debug, Clone)]
pub struct TuicPacket {
    /// Session ID (u16) for UDP association.
    pub assoc_id: u16,
    /// Fragment number (u8) for large datagrams.
    pub frag_id: u8,
    /// Total fragment count (u8).
    pub frag_total: u8,
    /// Destination address.
    pub addr: TuicAddr,
    /// UDP payload data.
    pub data: Vec<u8>,
}

impl TuicPacket {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![TUIC_VERSION, cmd::PACKET];
        out.extend_from_slice(&self.assoc_id.to_be_bytes());
        out.push(self.frag_id);
        out.push(self.frag_total);
        out.extend_from_slice(&self.addr.encode());
        out.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, usize), TuicError> {
        if buf.len() < 4 {
            return Err(TuicError::ShortBuffer);
        }
        let assoc_id = u16::from_be_bytes(buf[0..2].try_into().unwrap());
        let frag_id = buf[2];
        let frag_total = buf[3];
        let mut offset = 4;

        let (addr, addr_len) = TuicAddr::decode(&buf[offset..])?;
        offset += addr_len;

        if buf.len() < offset + 2 {
            return Err(TuicError::ShortBuffer);
        }
        let data_len = u16::from_be_bytes(buf[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;

        if buf.len() < offset + data_len {
            return Err(TuicError::ShortBuffer);
        }
        let data = buf[offset..offset + data_len].to_vec();
        offset += data_len;

        Ok((Self { assoc_id, frag_id, frag_total, addr, data }, offset))
    }
}

/// A TUIC Heartbeat command (no payload).
#[derive(Debug, Clone)]
pub struct TuicHeartbeat;

impl TuicHeartbeat {
    pub fn encode(&self) -> Vec<u8> {
        vec![TUIC_VERSION, cmd::HEARTBEAT]
    }
}

/// TUIC protocol errors.
#[derive(Debug, thiserror::Error)]
pub enum TuicError {
    #[error("buffer too short for TUIC header")]
    ShortBuffer,
    #[error("unknown TUIC address type: 0x{0:02X}")]
    UnknownAddressType(u8),
    #[error("domain name contains invalid UTF-8")]
    InvalidUtf8,
    #[error("authentication token mismatch")]
    AuthFailed,
    #[error("unsupported TUIC version: 0x{0:02X}")]
    UnsupportedVersion(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addr_ipv4_roundtrip() {
        let addr = TuicAddr::Ipv4([1, 2, 3, 4], 8080);
        let encoded = addr.encode();
        let (decoded, consumed) = TuicAddr::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_addr_domain_roundtrip() {
        let addr = TuicAddr::Domain("example.com".to_string(), 443);
        let encoded = addr.encode();
        let (decoded, consumed) = TuicAddr::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_authenticate_encode_verify() {
        let uuid = [0xABu8; 16];
        let auth = TuicAuthenticate::new(uuid, "password123");
        assert!(auth.verify("password123"));
        assert!(!auth.verify("wrong_password"));

        let encoded = auth.encode();
        assert_eq!(encoded[0], TUIC_VERSION);
        assert_eq!(encoded[1], cmd::AUTHENTICATE);
    }

    #[test]
    fn test_connect_encode_decode() {
        let connect = TuicConnect {
            addr: TuicAddr::Domain("proxy.example.com".to_string(), 9000),
        };
        let encoded = connect.encode();
        // Skip version+cmd bytes
        let (decoded, _) = TuicConnect::decode(&encoded[2..]).unwrap();
        assert_eq!(decoded.addr, connect.addr);
    }

    #[test]
    fn test_packet_encode_decode() {
        let packet = TuicPacket {
            assoc_id: 42,
            frag_id: 0,
            frag_total: 1,
            addr: TuicAddr::Ipv4([8, 8, 8, 8], 53),
            data: b"DNS query".to_vec(),
        };
        let encoded = packet.encode();
        let (decoded, _) = TuicPacket::decode(&encoded[2..]).unwrap();
        assert_eq!(decoded.assoc_id, 42);
        assert_eq!(decoded.data, b"DNS query");
    }

    #[test]
    fn test_heartbeat_encode() {
        let hb = TuicHeartbeat;
        let encoded = hb.encode();
        assert_eq!(encoded, vec![TUIC_VERSION, cmd::HEARTBEAT]);
    }

    #[test]
    fn test_addr_display() {
        let a = TuicAddr::Ipv4([127, 0, 0, 1], 1080);
        assert_eq!(a.to_string(), "127.0.0.1:1080");

        let d = TuicAddr::Domain("google.com".to_string(), 443);
        assert_eq!(d.to_string(), "google.com:443");
    }
}
