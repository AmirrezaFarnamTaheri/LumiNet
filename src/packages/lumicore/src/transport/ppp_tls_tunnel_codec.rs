//! # PPP TLS Tunnel Codec
//!
//! Point-to-Point Protocol (PPP) over TLS tunnel framing engine implementing
//! HDLC byte-stuffing, LCP/IPCP protocol identification, and IP packet encapsulation.

use serde::{Deserialize, Serialize};

pub const PPP_FRAME_DELIMITER: u8 = 0x7e;
pub const PPP_ESCAPE_BYTE: u8 = 0x7d;
pub const PPP_ESCAPE_XOR: u8 = 0x20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PppProtocol {
    Ipv4 = 0x0021,
    Ipv6 = 0x0057,
    Lcp = 0xc021,
    Ipcp = 0x8021,
    Unknown = 0xffff,
}

impl From<u16> for PppProtocol {
    fn from(val: u16) -> Self {
        match val {
            0x0021 => PppProtocol::Ipv4,
            0x0057 => PppProtocol::Ipv6,
            0xc021 => PppProtocol::Lcp,
            0x8021 => PppProtocol::Ipcp,
            _ => PppProtocol::Unknown,
        }
    }
}

pub struct PppTlsTunnelCodec;

impl PppTlsTunnelCodec {
    pub fn encode_frame(proto: PppProtocol, payload: &[u8]) -> Vec<u8> {
        let mut unescaped = Vec::with_capacity(4 + payload.len());
        unescaped.push(0xff); // All-stations broadcast address
        unescaped.push(0x03); // Control byte: Unnumbered Information

        let proto_val = proto as u16;
        unescaped.push((proto_val >> 8) as u8);
        unescaped.push((proto_val & 0xff) as u8);
        unescaped.extend_from_slice(payload);

        // Compute 16-bit CRC-CCITT (FCS)
        let fcs = Self::compute_fcs(&unescaped);
        unescaped.push((fcs & 0xff) as u8);
        unescaped.push((fcs >> 8) as u8);

        // HDLC byte stuffing
        let mut framed = Vec::new();
        framed.push(PPP_FRAME_DELIMITER);

        for &b in &unescaped {
            if b == PPP_FRAME_DELIMITER || b == PPP_ESCAPE_BYTE || b < 0x20 {
                framed.push(PPP_ESCAPE_BYTE);
                framed.push(b ^ PPP_ESCAPE_XOR);
            } else {
                framed.push(b);
            }
        }

        framed.push(PPP_FRAME_DELIMITER);
        framed
    }

    pub fn decode_frame(framed_data: &[u8]) -> Result<(PppProtocol, Vec<u8>), String> {
        if framed_data.len() < 6 {
            return Err("Frame too small".to_string());
        }

        // Strip delimiters and unescape bytes
        let mut unescaped = Vec::new();
        let mut i = 0;

        // Skip leading delimiter
        while i < framed_data.len() && framed_data[i] == PPP_FRAME_DELIMITER {
            i += 1;
        }

        while i < framed_data.len() {
            let b = framed_data[i];
            if b == PPP_FRAME_DELIMITER {
                break;
            } else if b == PPP_ESCAPE_BYTE {
                i += 1;
                if i >= framed_data.len() {
                    return Err("Truncated escape sequence".to_string());
                }
                unescaped.push(framed_data[i] ^ PPP_ESCAPE_XOR);
            } else {
                unescaped.push(b);
            }
            i += 1;
        }

        if unescaped.len() < 6 {
            return Err("Decoded frame payload too short".to_string());
        }

        // Verify FCS (last 2 bytes)
        let received_fcs = (unescaped[unescaped.len() - 1] as u16) << 8 | (unescaped[unescaped.len() - 2] as u16);
        let expected_fcs = Self::compute_fcs(&unescaped[..unescaped.len() - 2]);
        if received_fcs != expected_fcs {
            return Err("FCS verification failed".to_string());
        }

        let proto_val = ((unescaped[2] as u16) << 8) | (unescaped[3] as u16);
        let proto = PppProtocol::from(proto_val);
        let payload = unescaped[4..unescaped.len() - 2].to_vec();

        Ok((proto, payload))
    }

    fn compute_fcs(data: &[u8]) -> u16 {
        let mut fcs: u16 = 0xffff;
        for &b in data {
            let mut byte = b as u16;
            for _ in 0..8 {
                if ((fcs ^ byte) & 0x0001) != 0 {
                    fcs = (fcs >> 1) ^ 0x8408;
                } else {
                    fcs >>= 1;
                }
                byte >>= 1;
            }
        }
        !fcs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ppp_hdlc_encode_decode_roundtrip() {
        let ip_payload = b"\x45\x00\x00\x28\x12\x34\x40\x00\x40\x06\x7f\x00\x00\x01\x7f\x00\x00\x01";
        let framed = PppTlsTunnelCodec::encode_frame(PppProtocol::Ipv4, ip_payload);

        assert_eq!(framed[0], PPP_FRAME_DELIMITER);
        assert_eq!(framed[framed.len() - 1], PPP_FRAME_DELIMITER);

        let (proto, decoded) = PppTlsTunnelCodec::decode_frame(&framed).unwrap();
        assert_eq!(proto, PppProtocol::Ipv4);
        assert_eq!(decoded, ip_payload);
    }
}
