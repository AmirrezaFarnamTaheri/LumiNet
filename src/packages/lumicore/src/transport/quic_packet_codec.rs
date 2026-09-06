//! # QUIC Packet Codec
//!
//! Bit-level QUIC packet parser and serializer implementing Long Header (Initial, Handshake, Retry)
//! and Short Header (1-RTT) framing, RFC 9000 variable-length integers, and CID management.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuicHeaderType {
    Initial = 0x00,
    ZeroRtt = 0x01,
    Handshake = 0x02,
    Retry = 0x03,
    OneRttShort = 0x04,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuicPacketHeader {
    pub header_type: QuicHeaderType,
    pub version: u32,
    pub dest_cid: Vec<u8>,
    pub src_cid: Vec<u8>,
    pub packet_number: u64,
}

pub struct QuicPacketCodec;

impl QuicPacketCodec {
    pub fn encode_varint(value: u64) -> Vec<u8> {
        if value < (1 << 6) {
            vec![value as u8]
        } else if value < (1 << 14) {
            vec![0x40 | ((value >> 8) as u8), (value & 0xff) as u8]
        } else if value < (1 << 30) {
            let mut out = vec![0x80 | ((value >> 24) as u8)];
            out.push(((value >> 16) & 0xff) as u8);
            out.push(((value >> 8) & 0xff) as u8);
            out.push((value & 0xff) as u8);
            out
        } else {
            let mut out = vec![0xc0 | ((value >> 56) as u8)];
            for i in (0..7).rev() {
                out.push(((value >> (i * 8)) & 0xff) as u8);
            }
            out
        }
    }

    pub fn decode_varint(data: &[u8]) -> Result<(u64, usize), String> {
        if data.is_empty() {
            return Err("Unexpected EOF reading varint".to_string());
        }

        let prefix = data[0] >> 6;
        match prefix {
            0 => Ok((data[0] as u64, 1)),
            1 => {
                if data.len() < 2 {
                    return Err("Varint truncated at 2 bytes".to_string());
                }
                let val = (((data[0] & 0x3f) as u64) << 8) | (data[1] as u64);
                Ok((val, 2))
            }
            2 => {
                if data.len() < 4 {
                    return Err("Varint truncated at 4 bytes".to_string());
                }
                let val = (((data[0] & 0x3f) as u64) << 24)
                    | ((data[1] as u64) << 16)
                    | ((data[2] as u64) << 8)
                    | (data[3] as u64);
                Ok((val, 4))
            }
            3 => {
                if data.len() < 8 {
                    return Err("Varint truncated at 8 bytes".to_string());
                }
                let mut val = ((data[0] & 0x3f) as u64) << 56;
                for i in 1..8 {
                    val |= (data[i] as u64) << ((7 - i) * 8);
                }
                Ok((val, 8))
            }
            _ => unreachable!(),
        }
    }

    pub fn encode_packet(header: &QuicPacketHeader, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();

        match header.header_type {
            QuicHeaderType::OneRttShort => {
                // Short header: Form bit (0), Fixed bit (1), Spin (0), Reserved (00), KeyPhase (0), PN length (2 bytes = 01)
                let first_byte = 0x40 | 0x01;
                out.push(first_byte);
                out.extend_from_slice(&header.dest_cid);
                out.extend_from_slice(&(header.packet_number as u16).to_be_bytes());
                out.extend_from_slice(payload);
            }
            long_type => {
                // Long header: Form bit (1), Fixed bit (1), Long packet type (2 bits)
                let type_bits = match long_type {
                    QuicHeaderType::Initial => 0x00,
                    QuicHeaderType::ZeroRtt => 0x10,
                    QuicHeaderType::Handshake => 0x20,
                    QuicHeaderType::Retry => 0x30,
                    QuicHeaderType::OneRttShort => unreachable!(),
                };
                let first_byte = 0x80 | 0x40 | type_bits;
                out.push(first_byte);
                out.extend_from_slice(&header.version.to_be_bytes());

                // Dest CID
                out.push(header.dest_cid.len() as u8);
                out.extend_from_slice(&header.dest_cid);

                // Src CID
                out.push(header.src_cid.len() as u8);
                out.extend_from_slice(&header.src_cid);

                // Length of token + payload + PN
                let pn_bytes = (header.packet_number as u16).to_be_bytes();
                let length_varint = Self::encode_varint((pn_bytes.len() + payload.len()) as u64);
                out.extend_from_slice(&length_varint);

                out.extend_from_slice(&pn_bytes);
                out.extend_from_slice(payload);
            }
        }

        out
    }

    pub fn decode_packet(data: &[u8], dest_cid_len: usize) -> Result<(QuicPacketHeader, Vec<u8>), String> {
        if data.is_empty() {
            return Err("Empty packet".to_string());
        }

        let first_byte = data[0];
        let is_long_header = (first_byte & 0x80) != 0;

        if is_long_header {
            if data.len() < 7 {
                return Err("Long header truncated".to_string());
            }

            let type_bits = (first_byte & 0x30) >> 4;
            let header_type = match type_bits {
                0x00 => QuicHeaderType::Initial,
                0x01 => QuicHeaderType::ZeroRtt,
                0x02 => QuicHeaderType::Handshake,
                0x03 => QuicHeaderType::Retry,
                _ => unreachable!(),
            };

            let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
            let mut offset = 5;

            let dcid_len = data[offset] as usize;
            offset += 1;
            if offset + dcid_len > data.len() {
                return Err("DCID truncated".to_string());
            }
            let dest_cid = data[offset..offset + dcid_len].to_vec();
            offset += dcid_len;

            if offset >= data.len() {
                return Err("SCID len truncated".to_string());
            }
            let scid_len = data[offset] as usize;
            offset += 1;
            if offset + scid_len > data.len() {
                return Err("SCID truncated".to_string());
            }
            let src_cid = data[offset..offset + scid_len].to_vec();
            offset += scid_len;

            let (payload_len, varint_len) = Self::decode_varint(&data[offset..])?;
            offset += varint_len;

            if offset + 2 > data.len() {
                return Err("Packet number truncated".to_string());
            }
            let packet_number = u16::from_be_bytes([data[offset], data[offset + 1]]) as u64;
            offset += 2;

            let payload_size = (payload_len as usize).saturating_sub(2);
            if offset + payload_size > data.len() {
                return Err("Payload truncated".to_string());
            }
            let payload = data[offset..offset + payload_size].to_vec();

            Ok((
                QuicPacketHeader {
                    header_type,
                    version,
                    dest_cid,
                    src_cid,
                    packet_number,
                },
                payload,
            ))
        } else {
            // Short header
            let mut offset = 1;
            if offset + dest_cid_len + 2 > data.len() {
                return Err("Short header truncated".to_string());
            }
            let dest_cid = data[offset..offset + dest_cid_len].to_vec();
            offset += dest_cid_len;

            let packet_number = u16::from_be_bytes([data[offset], data[offset + 1]]) as u64;
            offset += 2;

            let payload = data[offset..].to_vec();
            Ok((
                QuicPacketHeader {
                    header_type: QuicHeaderType::OneRttShort,
                    version: 0,
                    dest_cid,
                    src_cid: Vec::new(),
                    packet_number,
                },
                payload,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_codec() {
        let values = [0, 42, 63, 64, 1500, 16383, 16384, 1073741823, 1073741824];
        for &v in &values {
            let encoded = QuicPacketCodec::encode_varint(v);
            let (decoded, len) = QuicPacketCodec::decode_varint(&encoded).unwrap();
            assert_eq!(v, decoded);
            assert_eq!(encoded.len(), len);
        }
    }

    #[test]
    fn test_long_header_initial_packet() {
        let header = QuicPacketHeader {
            header_type: QuicHeaderType::Initial,
            version: 1,
            dest_cid: vec![0x01, 0x02, 0x03, 0x04],
            src_cid: vec![0x05, 0x06, 0x07, 0x08],
            packet_number: 100,
        };

        let payload = b"ping_quic_frame_payload";
        let encoded = QuicPacketCodec::encode_packet(&header, payload);

        let (decoded_hdr, decoded_payload) = QuicPacketCodec::decode_packet(&encoded, 4).unwrap();
        assert_eq!(decoded_hdr, header);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_short_header_1rtt_packet() {
        let header = QuicPacketHeader {
            header_type: QuicHeaderType::OneRttShort,
            version: 0,
            dest_cid: vec![0xaa, 0xbb, 0xcc, 0xdd],
            src_cid: Vec::new(),
            packet_number: 55,
        };

        let payload = b"app_data_stream";
        let encoded = QuicPacketCodec::encode_packet(&header, payload);

        let (decoded_hdr, decoded_payload) = QuicPacketCodec::decode_packet(&encoded, 4).unwrap();
        assert_eq!(decoded_hdr.header_type, QuicHeaderType::OneRttShort);
        assert_eq!(decoded_hdr.dest_cid, header.dest_cid);
        assert_eq!(decoded_hdr.packet_number, 55);
        assert_eq!(decoded_payload, payload);
    }
}
