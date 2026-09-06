//! Relay Stream Header Framing Codec
//!
//! Encapsulates downstream/upstream relay connection initiation headers.
//! Supports V1 delimiter-based streaming protocol (`<net>@<address>$<port>\r`)
//! and V2 compact binary wire protocol.

use std::fmt;

/// Target transport protocol for relay forwarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayNetwork {
    Tcp,
    Udp,
}

impl RelayNetwork {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Relay stream destination address header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayStreamHeader {
    pub network: RelayNetwork,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayCodecError {
    EmptyBuffer,
    MissingDelimiter(&'static str),
    InvalidNetwork(String),
    InvalidPort(String),
    BufferTooShort,
    InvalidMagic,
    InvalidUtf8,
}

impl fmt::Display for RelayCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyBuffer => write!(f, "empty buffer"),
            Self::MissingDelimiter(d) => write!(f, "missing delimiter '{}'", d),
            Self::InvalidNetwork(s) => write!(f, "invalid relay network '{}', expected tcp or udp", s),
            Self::InvalidPort(s) => write!(f, "invalid port string '{}'", s),
            Self::BufferTooShort => write!(f, "buffer too short for relay header"),
            Self::InvalidMagic => write!(f, "invalid relay v2 magic bytes"),
            Self::InvalidUtf8 => write!(f, "invalid utf-8 in relay header"),
        }
    }
}

impl std::error::Error for RelayCodecError {}

impl RelayStreamHeader {
    pub fn new(network: RelayNetwork, host: impl Into<String>, port: u16) -> Self {
        Self {
            network,
            host: host.into(),
            port,
        }
    }

    /// Encodes to V1 ASCII wire format: `<network>@<host>$<port>\r`.
    pub fn encode_v1(&self) -> Vec<u8> {
        let s = format!("{}@{}${}\r", self.network.as_str(), self.host, self.port);
        s.into_bytes()
    }

    /// Decodes from V1 byte slice terminating with `\r` (byte 13).
    /// Returns the header and number of bytes consumed (including `\r`).
    pub fn decode_v1(src: &[u8]) -> Result<(Self, usize), RelayCodecError> {
        if src.is_empty() {
            return Err(RelCodecError::EmptyBuffer);
        }

        // Find carriage return '\r' (byte 13)
        let cr_pos = src.iter().position(|&b| b == b'\r')
            .ok_or(RelayCodecError::MissingDelimiter("\\r"))?;

        let header_slice = &src[..cr_pos];
        let at_pos = header_slice.iter().position(|&b| b == b'@')
            .ok_or(RelayCodecError::MissingDelimiter("@"))?;

        let net_str = std::str::from_utf8(&header_slice[..at_pos])
            .map_err(|_| RelayCodecError::InvalidUtf8)?;

        let network = match net_str.to_ascii_lowercase().as_str() {
            "tcp" => RelayNetwork::Tcp,
            "udp" => RelayNetwork::Udp,
            other => return Err(RelayCodecError::InvalidNetwork(other.to_string())),
        };

        let rest = &header_slice[at_pos + 1..];
        let dollar_pos = rest.iter().position(|&b| b == b'$')
            .ok_or(RelayCodecError::MissingDelimiter("$"))?;

        let host = std::str::from_utf8(&rest[..dollar_pos])
            .map_err(|_| RelayCodecError::InvalidUtf8)?
            .to_string();

        let port_str = std::str::from_utf8(&rest[dollar_pos + 1..])
            .map_err(|_| RelayCodecError::InvalidUtf8)?;
        let port = port_str.parse::<u16>()
            .map_err(|_| RelayCodecError::InvalidPort(port_str.to_string()))?;

        Ok((Self { network, host, port }, cr_pos + 1))
    }

    /// Encodes to V2 compact binary wire format:
    /// Magic: [0x52, 0x32] ('R2') + NetByte (1=TCP, 2=UDP) + Port (u16 BE) + HostLen (u8) + HostBytes
    pub fn encode_v2(&self) -> Vec<u8> {
        let host_bytes = self.host.as_bytes();
        let mut out = Vec::with_capacity(2 + 1 + 2 + 1 + host_bytes.len());
        out.extend_from_slice(b"R2");
        out.push(match self.network {
            RelayNetwork::Tcp => 1,
            RelayNetwork::Udp => 2,
        });
        out.extend_from_slice(&self.port.to_be_bytes());
        out.push(host_bytes.len().min(255) as u8);
        out.extend_from_slice(&host_bytes[..host_bytes.len().min(255)]);
        out
    }

    /// Decodes from V2 binary wire format.
    pub fn decode_v2(src: &[u8]) -> Result<(Self, usize), RelayCodecError> {
        if src.len() < 6 {
            return Err(RelayCodecError::BufferTooShort);
        }

        if &src[0..2] != b"R2" {
            return Err(RelayCodecError::InvalidMagic);
        }

        let network = match src[2] {
            1 => RelayNetwork::Tcp,
            2 => RelayNetwork::Udp,
            other => return Err(RelayCodecError::InvalidNetwork(format!("type {}", other))),
        };

        let port = u16::from_be_bytes([src[3], src[4]]);
        let host_len = src[5] as usize;
        let total_len = 6 + host_len;

        if src.len() < total_len {
            return Err(RelayCodecError::BufferTooShort);
        }

        let host = std::str::from_utf8(&src[6..total_len])
            .map_err(|_| RelayCodecError::InvalidUtf8)?
            .to_string();

        Ok((Self { network, host, port }, total_len))
    }
}

type RelCodecError = RelayCodecError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v1_tcp_roundtrip() {
        let header = RelayStreamHeader::new(RelayNetwork::Tcp, "1.1.1.1", 443);
        let encoded = header.encode_v1();
        assert_eq!(encoded, b"tcp@1.1.1.1$443\r");

        let (decoded, consumed) = RelayStreamHeader::decode_v1(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.network, RelayNetwork::Tcp);
        assert_eq!(decoded.host, "1.1.1.1");
        assert_eq!(decoded.port, 443);
    }

    #[test]
    fn test_v1_udp_hostname_roundtrip() {
        let header = RelayStreamHeader::new(RelayNetwork::Udp, "dns.google", 53);
        let encoded = header.encode_v1();
        assert_eq!(encoded, b"udp@dns.google$53\r");

        let (decoded, consumed) = RelayStreamHeader::decode_v1(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.network, RelayNetwork::Udp);
        assert_eq!(decoded.host, "dns.google");
        assert_eq!(decoded.port, 53);
    }

    #[test]
    fn test_v2_roundtrip() {
        let header = RelayStreamHeader::new(RelayNetwork::Tcp, "proxy.edge.internal", 8443);
        let encoded = header.encode_v2();
        assert_eq!(&encoded[0..2], b"R2");

        let (decoded, consumed) = RelayStreamHeader::decode_v2(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.network, RelayNetwork::Tcp);
        assert_eq!(decoded.host, "proxy.edge.internal");
        assert_eq!(decoded.port, 8443);
    }
}
