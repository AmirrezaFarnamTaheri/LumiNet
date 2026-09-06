//
// WebSocket-bridged Tor cell extensions. node-Tor defines three non-standard
// cell command codes for transporting Tor cells over a WebSocket framing
// layer:
//   CREATE_FAST_WS   = 120
//   CREATED_FAST_WS  = 121
//   RELAY_WS         = 190
//
// These extend the fixed-cell parser in `tor_cells.rs` for WS transports.
// Source: node-Tor `circuits.js` constants + `cells.js` `Payload` dispatch.

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WsCellCommand {
    CreateFast = 120,
    CreatedFast = 121,
    Relay = 190,
    Unknown(u8) = 0xFF,
}

impl WsCellCommand {
    pub fn from_u8(b: u8) -> Self {
        match b {
            120 => Self::CreateFast,
            121 => Self::CreatedFast,
            190 => Self::Relay,
            other => Self::Unknown(other),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::CreateFast => 120,
            Self::CreatedFast => 121,
            Self::Relay => 190,
            Self::Unknown(b) => b,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::CreateFast => "CREATE_FAST_WS",
            Self::CreatedFast => "CREATED_FAST_WS",
            Self::Relay => "RELAY_WS",
            Self::Unknown(_) => "UNKNOWN_WS",
        }
    }
}

#[derive(Debug, Error)]
pub enum WsCellError {
    #[error("WS cell payload too short: got {got}, need {need}")]
    Truncated { got: usize, need: usize },
}

/// A WS-bridged Tor cell. Wire layout mirrors fixed cells but with
/// WS-specific command codes and no circ_id prefix (circ_id is embedded
/// in the WS frame metadata at a higher layer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsCell {
    pub command: WsCellCommand,
    pub payload: Vec<u8>,
}

impl WsCell {
    /// Minimum payload length for each command.
    pub fn min_payload_len(cmd: WsCellCommand) -> usize {
        match cmd {
            WsCellCommand::CreateFast | WsCellCommand::CreatedFast => 20,
            WsCellCommand::Relay => 11,
            WsCellCommand::Unknown(_) => 0,
        }
    }

    /// Parse a WS cell from raw bytes (command byte + payload).
    pub fn parse(buf: &[u8]) -> Result<Self, WsCellError> {
        if buf.is_empty() {
            return Err(WsCellError::Truncated { got: 0, need: 1 });
        }
        let cmd = WsCellCommand::from_u8(buf[0]);
        let payload = buf[1..].to_vec();
        Ok(Self {
            command: cmd,
            payload,
        })
    }

    /// Serialize to command byte + payload.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.payload.len());
        out.push(self.command.to_u8());
        out.extend_from_slice(&self.payload);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_cell_codes_roundtrip() {
        assert_eq!(WsCellCommand::from_u8(120), WsCellCommand::CreateFast);
        assert_eq!(WsCellCommand::from_u8(121), WsCellCommand::CreatedFast);
        assert_eq!(WsCellCommand::from_u8(190), WsCellCommand::Relay);
        assert_eq!(WsCellCommand::from_u8(0xFF), WsCellCommand::Unknown(0xFF));
        assert_eq!(WsCellCommand::CreateFast.to_u8(), 120);
    }

    #[test]
    fn parse_and_serialize_roundtrip() {
        let cell = WsCell {
            command: WsCellCommand::Relay,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let wire = cell.serialize();
        assert_eq!(&wire[0..1], &[190]);
        let back = WsCell::parse(&wire).unwrap();
        assert_eq!(back, cell);
    }

    #[test]
    fn create_fast_needs_20_byte_payload() {
        assert_eq!(WsCell::min_payload_len(WsCellCommand::CreateFast), 20);
    }
}
