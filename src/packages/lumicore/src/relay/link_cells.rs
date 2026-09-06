//
// Link-layer Tor cell decoders for the v3 handshake. tor_cells.rs covers
// the fixed 514-byte relay cells; this module handles the variable-length
// link-layer cells that appear during the initial handshake before any
// circuit is established:
//   - CERTS            (command 129)
//   - AUTH_CHALLENGE   (command 130)
//   - NETINFO          (command 8 — also in tor_cells.rs, repeated here
//                        for the link-protocol variant without circ_id)
//   - VERSIONS         (command 7)
//
// Source: node-Tor lib/src/cells.js `certs_cell_decode`, `netinfo_cell_decode`,
// `versions_cell_decode`. Cross-reference: tor_cells.rs `CellCommand` covers
// NetInfo at command 8; this module adds the link-protocol decoders that
// appear on the wire before the fixed-cell protocol is negotiated.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum LinkCellError {
    #[error("link cell payload too short: got {got}, need {need}")]
    Truncated { got: usize, need: usize },
    #[error("unsupported link cell command {0}")]
    UnknownCommand(u8),
    #[error("malformed cert list: {0}")]
    BadCertList(&'static str),
}

/// Link-layer cell commands (v3 handshake, no circ_id prefix).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkCellCommand {
    Padding = 0,
    Create = 1,
    Created = 2,
    Relay = 3,
    Destroy = 4,
    NetInfo = 8,
    Versions = 7,
    Certs = 129,
    AuthChallenge = 130,
    Unknown(u8) = 0xFF,
}

impl LinkCellCommand {
    pub fn from_u8(b: u8) -> Self {
        match b {
            0 => Self::Padding,
            1 => Self::Create,
            2 => Self::Created,
            3 => Self::Relay,
            4 => Self::Destroy,
            7 => Self::Versions,
            8 => Self::NetInfo,
            129 => Self::Certs,
            130 => Self::AuthChallenge,
            other => Self::Unknown(other),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::Padding => 0,
            Self::Create => 1,
            Self::Created => 2,
            Self::Relay => 3,
            Self::Destroy => 4,
            Self::Versions => 7,
            Self::NetInfo => 8,
            Self::Certs => 129,
            Self::AuthChallenge => 130,
            Self::Unknown(b) => b,
        }
    }
}

// ─── CERTS cell ───────────────────────────────────────────────────────────

/// One certificate entry inside a CERTS cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertEntry {
    pub cert_type: u8,
    pub cert_bytes: Vec<u8>,
}

/// Decoded CERTS cell payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertsCell {
    pub entries: Vec<CertEntry>,
}

impl CertsCell {
    /// Parse a CERTS cell from raw payload bytes.
    pub fn parse(buf: &[u8]) -> Result<Self, LinkCellError> {
        let mut entries = Vec::new();
        let mut cursor = 0usize;
        while cursor + 3 <= buf.len() {
            let cert_type = buf[cursor];
            let clen = u16::from_be_bytes([buf[cursor + 1], buf[cursor + 2]]) as usize;
            cursor += 3;
            if cursor + clen > buf.len() {
                return Err(LinkCellError::BadCertList("cert length exceeds payload"));
            }
            let cert_bytes = buf[cursor..cursor + clen].to_vec();
            cursor += clen;
            entries.push(CertEntry {
                cert_type,
                cert_bytes,
            });
        }
        Ok(Self { entries })
    }
}

// ─── AUTH_CHALLENGE cell ──────────────────────────────────────────────────

/// Decoded AUTH_CHALLENGE cell payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthChallengeCell {
    pub challenge: Vec<u8>,
}

impl AuthChallengeCell {
    pub fn parse(buf: &[u8]) -> Result<Self, LinkCellError> {
        if buf.len() < 32 {
            return Err(LinkCellError::Truncated {
                got: buf.len(),
                need: 32,
            });
        }
        Ok(Self {
            challenge: buf[..32].to_vec(),
        })
    }
}

// ─── VERSIONS cell ────────────────────────────────────────────────────────

/// Decoded VERSIONS cell payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionsCell {
    pub versions: Vec<u16>,
}

impl VersionsCell {
    pub fn parse(buf: &[u8]) -> Result<Self, LinkCellError> {
        if buf.len() < 2 {
            return Err(LinkCellError::Truncated {
                got: buf.len(),
                need: 2,
            });
        }
        let mut versions = Vec::new();
        let mut cursor = 0usize;
        while cursor + 2 <= buf.len() {
            versions.push(u16::from_be_bytes([buf[cursor], buf[cursor + 1]]));
            cursor += 2;
        }
        Ok(Self { versions })
    }
}

// ─── NETINFO cell (link-protocol variant, no circ_id) ─────────────────────

/// Decoded NETINFO cell payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetInfoCell {
    pub timestamp: u32,
    pub other_or: std::net::Ipv4Addr,
    pub addresses: Vec<std::net::Ipv4Addr>,
}

impl NetInfoCell {
    pub fn parse(buf: &[u8]) -> Result<Self, LinkCellError> {
        if buf.len() < 8 {
            return Err(LinkCellError::Truncated {
                got: buf.len(),
                need: 8,
            });
        }
        let timestamp = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let other_or = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
        let mut addresses = Vec::new();
        let mut cursor = 8usize;
        if cursor + 1 > buf.len() {
            return Ok(Self {
                timestamp,
                other_or,
                addresses,
            });
        }
        let nb = buf[cursor] as usize;
        cursor += 1;
        for _ in 0..nb {
            if cursor + 4 > buf.len() {
                break;
            }
            addresses.push(std::net::Ipv4Addr::new(
                buf[cursor],
                buf[cursor + 1],
                buf[cursor + 2],
                buf[cursor + 3],
            ));
            cursor += 4;
        }
        Ok(Self {
            timestamp,
            other_or,
            addresses,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_certs_cell() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x01, 0x00, 0x03]); // type=1, len=3
        buf.extend_from_slice(b"abc");
        let cell = CertsCell::parse(&buf).unwrap();
        assert_eq!(cell.entries.len(), 1);
        assert_eq!(cell.entries[0].cert_type, 1);
        assert_eq!(cell.entries[0].cert_bytes, b"abc");
    }

    #[test]
    fn parse_auth_challenge() {
        let challenge = [0xABu8; 32];
        let cell = AuthChallengeCell::parse(&challenge).unwrap();
        assert_eq!(cell.challenge.len(), 32);
        assert_eq!(cell.challenge[0], 0xAB);
    }

    #[test]
    fn parse_versions() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x00, 0x04]); // v4
        buf.extend_from_slice(&[0x00, 0x05]); // v5
        let cell = VersionsCell::parse(&buf).unwrap();
        assert_eq!(cell.versions, vec![4, 5]);
    }

    #[test]
    fn parse_netinfo() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // timestamp=1
        buf.extend_from_slice(&[10, 0, 0, 1]); // other_or=10.0.0.1
        buf.push(1); // 1 address
        buf.extend_from_slice(&[192, 168, 1, 1]); // addr=192.168.1.1
        let cell = NetInfoCell::parse(&buf).unwrap();
        assert_eq!(cell.timestamp, 1);
        assert_eq!(cell.other_or, std::net::Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(
            cell.addresses,
            vec![std::net::Ipv4Addr::new(192, 168, 1, 1)]
        );
    }

    #[test]
    fn unknown_command_roundtrip() {
        assert_eq!(LinkCellCommand::from_u8(255), LinkCellCommand::Unknown(255));
        assert_eq!(LinkCellCommand::Unknown(255).to_u8(), 255);
    }
}
