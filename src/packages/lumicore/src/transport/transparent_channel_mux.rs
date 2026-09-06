//! # Transparent TCP Channel Multiplexing Framing
//!
//! Handles multiplexed stream redirection over a single transport stream
//! with 4-byte channel IDs and connection opcodes (CONNECT, DATA, EOF, CLOSE).

pub const CHANNEL_CMD_CONNECT: u8 = 0x01;
pub const CHANNEL_CMD_DATA: u8 = 0x02;
pub const CHANNEL_CMD_EOF: u8 = 0x03;
pub const CHANNEL_CMD_CLOSE: u8 = 0x04;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelMuxFrame {
    pub channel_id: u32,
    pub command: u8,
    pub payload: Vec<u8>,
}

impl ChannelMuxFrame {
    pub fn new_connect(channel_id: u32, target_host_port: &str) -> Self {
        Self {
            channel_id,
            command: CHANNEL_CMD_CONNECT,
            payload: target_host_port.as_bytes().to_vec(),
        }
    }

    pub fn new_data(channel_id: u32, data: &[u8]) -> Self {
        Self {
            channel_id,
            command: CHANNEL_CMD_DATA,
            payload: data.to_vec(),
        }
    }

    pub fn new_close(channel_id: u32) -> Self {
        Self {
            channel_id,
            command: CHANNEL_CMD_CLOSE,
            payload: Vec::new(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let len = self.payload.len() as u16;
        let mut buf = Vec::with_capacity(7 + self.payload.len());
        buf.extend_from_slice(&self.channel_id.to_be_bytes());
        buf.push(self.command);
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Result<(Self, usize), &'static str> {
        if bytes.len() < 7 {
            return Err("Buffer too short for channel mux frame header");
        }
        let mut cid_b = [0u8; 4];
        cid_b.copy_from_slice(&bytes[0..4]);
        let channel_id = u32::from_be_bytes(cid_b);
        let command = bytes[4];

        let mut len_b = [0u8; 2];
        len_b.copy_from_slice(&bytes[5..7]);
        let payload_len = u16::from_be_bytes(len_b) as usize;

        if bytes.len() < 7 + payload_len {
            return Err("Incomplete channel mux frame payload");
        }

        let payload = bytes[7..7 + payload_len].to_vec();
        Ok((Self { channel_id, command, payload }, 7 + payload_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_mux_frame_codec() {
        let frame = ChannelMuxFrame::new_connect(42, "example.com:80");
        let bytes = frame.serialize();
        let (parsed, consumed) = ChannelMuxFrame::deserialize(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.channel_id, 42);
        assert_eq!(parsed.command, CHANNEL_CMD_CONNECT);
        assert_eq!(String::from_utf8(parsed.payload).unwrap(), "example.com:80");
    }
}
