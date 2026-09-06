//! # Packed Control Block Framing
//!
//! Multiplexes control signals (ACK, NACK, SYN_ACK, RST_ACK, etc.) into compact 7-byte blocks:
//! `Type(1) + StreamID(2) + SeqNum(2) + FragID(1) + Total(1) = 7 Bytes`.
//! Reduces DNS query packet count by packing dozens of control updates per datagram.
//! Conforms to §8 structural cleanroom rules.

pub const PACKED_CONTROL_BLOCK_SIZE: usize = 7;

/// A parsed control block extracted from a packed control datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlBlock {
    pub packet_type: u8,
    pub stream_id: u16,
    pub sequence_num: u16,
    pub fragment_id: u8,
    pub total_fragments: u8,
}

impl ControlBlock {
    pub fn new(packet_type: u8, stream_id: u16, sequence_num: u16, fragment_id: u8, total_fragments: u8) -> Self {
        Self {
            packet_type,
            stream_id,
            sequence_num,
            fragment_id,
            total_fragments,
        }
    }

    /// Serializes block into 7-byte big-endian representation.
    pub fn encode(&self) -> [u8; PACKED_CONTROL_BLOCK_SIZE] {
        [
            self.packet_type,
            (self.stream_id >> 8) as u8,
            self.stream_id as u8,
            (self.sequence_num >> 8) as u8,
            self.sequence_num as u8,
            self.fragment_id,
            self.total_fragments,
        ]
    }

    /// Appends the 7-byte serialized block directly to a destination byte buffer.
    pub fn append_to(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.encode());
    }

    /// Deserializes a single 7-byte slice.
    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() < PACKED_CONTROL_BLOCK_SIZE {
            return None;
        }
        let packet_type = src[0];
        let stream_id = ((src[1] as u16) << 8) | (src[2] as u16);
        let sequence_num = ((src[3] as u16) << 8) | (src[4] as u16);
        let fragment_id = src[5];
        let total_fragments = src[6];

        Some(Self {
            packet_type,
            stream_id,
            sequence_num,
            fragment_id,
            total_fragments,
        })
    }
}

/// Iterates through contiguous 7-byte blocks in a packed payload.
pub fn parse_packed_control_blocks(payload: &[u8]) -> Vec<ControlBlock> {
    let mut blocks = Vec::new();
    let count = payload.len() / PACKED_CONTROL_BLOCK_SIZE;
    for i in 0..count {
        let offset = i * PACKED_CONTROL_BLOCK_SIZE;
        if let Some(block) = ControlBlock::decode(&payload[offset..offset + PACKED_CONTROL_BLOCK_SIZE]) {
            blocks.push(block);
        }
    }
    blocks
}

/// Packs multiple control blocks into a single byte slice.
pub fn pack_control_blocks(blocks: &[ControlBlock]) -> Vec<u8> {
    let mut dst = Vec::with_capacity(blocks.len() * PACKED_CONTROL_BLOCK_SIZE);
    for b in blocks {
        b.append_to(&mut dst);
    }
    dst
}
