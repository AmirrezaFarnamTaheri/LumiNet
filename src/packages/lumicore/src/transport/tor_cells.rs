//
// Raw fixed-length (514-byte) Tor cell parsing and serialization.
// Wire layout: [circ_id: u32 BE][command: u8][payload: 509 bytes] = 514 bytes total.
// Note: modern Tor link protocols use u64 circ_id on wire; the 514-byte fixed
// cell with u32 circ_id matches the legacy v1 link layer preserved by
// haskell-tor for parsing older relay captures. For current Tor versions
// the CRLF guard (`CIRC_ID_LEN`) should be parameterized — see upgrade path
// in the ponytail note at the bottom of this file.

use thiserror::Error;

/// Total length of a fixed Tor cell on the wire.
pub const FIXED_CELL_LEN: usize = 514;
/// CircID field width in bytes (legacy v1).
pub const CIRC_ID_LEN: usize = 4;
/// Payload bytes following the command byte.
pub const PAYLOAD_LEN: usize = 509;

/// Cell commands understood by the fixed-cell parser.
///
/// Names follow the Tor spec (`tor-spec.txt`). Values not listed here are
/// surfaced as `Command(unknown_value)` by [`FixedTorCell::command_kind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CellCommand {
    Padding = 0,
    Create = 1,
    Created = 2,
    Relay = 3,
    Destroy = 4,
    NetInfo = 8,
    Create2 = 10,
    /// Any command value not enumerated above.
    Unknown(u8) = 0xFF,
}

impl CellCommand {
    /// Parse a raw command byte into the enum.
    pub fn from_u8(b: u8) -> Self {
        match b {
            0 => Self::Padding,
            1 => Self::Create,
            2 => Self::Created,
            3 => Self::Relay,
            4 => Self::Destroy,
            8 => Self::NetInfo,
            10 => Self::Create2,
            other => Self::Unknown(other),
        }
    }

    /// Serialize the command back to its wire byte.
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Padding => 0,
            Self::Create => 1,
            Self::Created => 2,
            Self::Relay => 3,
            Self::Destroy => 4,
            Self::NetInfo => 8,
            Self::Create2 => 10,
            Self::Unknown(b) => b,
        }
    }

    /// String label matching the Tor spec name (for diagnostics).
    pub fn label(self) -> &'static str {
        match self {
            Self::Padding => "PADDING",
            Self::Create => "CREATE",
            Self::Created => "CREATED",
            Self::Relay => "RELAY",
            Self::Destroy => "DESTROY",
            Self::NetInfo => "NETINFO",
            Self::Create2 => "CREATE2",
            Self::Unknown(_) => "UNKNOWN",
        }
    }
}

/// A fixed-length 514-byte Tor cell.
///
/// The payload is a fixed-size array so the cell serialization/deserialization
/// is zero-copy and stack-stable; callers writing variable-length payloads
/// must zero-pad the remainder (helper [`FixedTorCell::with_payload`] handles
/// this automatically).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedTorCell {
    pub circ_id: u32,
    pub command: CellCommand,
    pub payload: [u8; PAYLOAD_LEN],
}

#[derive(Debug, Error)]
pub enum CellError {
    /// Input buffer was not exactly [`FIXED_CELL_LEN`] bytes.
    #[error("cell buffer must be exactly {expected} bytes, got {got}")]
    BadLength { expected: usize, got: usize },
}

impl FixedTorCell {
    /// Build a cell from a variable-length payload, zero-padding into the
    /// fixed 509-byte slot. Panics only if `payload.len() > PAYLOAD_LEN`.
    pub fn with_payload(circ_id: u32, command: CellCommand, payload: &[u8]) -> Self {
        assert!(
            payload.len() <= PAYLOAD_LEN,
            "payload exceeds {} bytes",
            PAYLOAD_LEN,
        );
        let mut buf = [0u8; PAYLOAD_LEN];
        buf[..payload.len()].copy_from_slice(payload);
        Self {
            circ_id,
            command,
            payload: buf,
        }
    }

    /// Parse a 514-byte cell from a raw buffer.
    pub fn parse(buf: &[u8]) -> Result<Self, CellError> {
        if buf.len() != FIXED_CELL_LEN {
            return Err(CellError::BadLength {
                expected: FIXED_CELL_LEN,
                got: buf.len(),
            });
        }
        let circ_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let command = CellCommand::from_u8(buf[4]);
        let mut payload = [0u8; PAYLOAD_LEN];
        payload.copy_from_slice(&buf[5..FIXED_CELL_LEN]);
        Ok(Self {
            circ_id,
            command,
            payload,
        })
    }

    /// Serialize this cell into a 514-byte buffer.
    pub fn serialize(&self) -> [u8; FIXED_CELL_LEN] {
        let mut out = [0u8; FIXED_CELL_LEN];
        out[0..4].copy_from_slice(&self.circ_id.to_be_bytes());
        out[4] = self.command.to_u8();
        out[5..FIXED_CELL_LEN].copy_from_slice(&self.payload);
        out
    }

    /// Convenience: borrow the payload slice (509 bytes).
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cell() -> FixedTorCell {
        let mut p = [0u8; PAYLOAD_LEN];
        p[0] = 0xDE;
        p[1] = 0xAD;
        p[508] = 0x42;
        FixedTorCell {
            circ_id: 0x01020304,
            command: CellCommand::Relay,
            payload: p,
        }
    }

    #[test]
    fn roundtrip_serialize_parse() {
        let cell = sample_cell();
        let wire = cell.serialize();
        assert_eq!(wire.len(), FIXED_CELL_LEN);
        assert_eq!(&wire[0..4], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(wire[4], CellCommand::Relay.to_u8());

        let back = FixedTorCell::parse(&wire).unwrap();
        assert_eq!(back, cell);
    }

    #[test]
    fn rejects_wrong_length() {
        let short = [0u8; 100];
        assert!(matches!(
            FixedTorCell::parse(&short),
            Err(CellError::BadLength { .. })
        ));
    }

    #[test]
    fn all_listed_commands_roundtrip() {
        for &cmd in &[
            CellCommand::Padding,
            CellCommand::Create,
            CellCommand::Created,
            CellCommand::Relay,
            CellCommand::Destroy,
            CellCommand::NetInfo,
            CellCommand::Create2,
        ] {
            assert_eq!(CellCommand::from_u8(cmd.to_u8()), cmd);
        }
    }

    #[test]
    fn unknown_command_is_preserved() {
        let cmd = CellCommand::from_u8(0x7F);
        assert!(matches!(cmd, CellCommand::Unknown(0x7F)));
        assert_eq!(cmd.to_u8(), 0x7F);
        assert_eq!(cmd.label(), "UNKNOWN");
    }

    #[test]
    fn with_payload_zero_pads() {
        let cell = FixedTorCell::with_payload(1, CellCommand::Create, &[0xAB, 0xCD]);
        assert_eq!(cell.payload[0], 0xAB);
        assert_eq!(cell.payload[1], 0xCD);
        assert_eq!(cell.payload[2..].iter().filter(|&&b| b != 0).count(), 0);
    }
}
// ponytail: 4-byte circ_id is legacy v1; current Tor link v4+
// uses 8-byte circ_id. If real Tor compatibility is needed,
// parameterize CIRC_ID_LEN (1..=8) per link-protocol version and
// swap FixedTorCell::parse/serialize to interpolate the width.
// Upgrade path: add `CellFmt::V4` enum variant -> 518-byte cell.
