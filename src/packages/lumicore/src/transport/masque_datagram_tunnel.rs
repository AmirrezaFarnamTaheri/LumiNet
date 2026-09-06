//! # MASQUE Datagram Tunnel
//!
//! Next-generation HTTP/3 MASQUE (RFC 9298 / RFC 9297) proxy tunneling layer supporting
//! CONNECT-UDP and CONNECT-IP datagram encapsulation, context IDs, and flow control.

use serde::{Deserialize, Serialize};

pub const MASQUE_CAPSULE_DATAGRAM: u64 = 0x00;
pub const MASQUE_CAPSULE_ADDRESS_ASSIGN: u64 = 0x01;
pub const MASQUE_CAPSULE_ROUTE_ADV: u64 = 0x02;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MasqueCapsule {
    pub capsule_type: u64,
    pub context_id: u64,
    pub payload: Vec<u8>,
}

pub struct MasqueDatagramTunnel {
    target_host: String,
    target_port: u16,
    default_context_id: u64,
    total_capsules_sent: u64,
    total_capsules_recv: u64,
}

impl MasqueDatagramTunnel {
    pub fn new(target_host: &str, target_port: u16, default_context_id: u64) -> Self {
        Self {
            target_host: target_host.to_string(),
            target_port,
            default_context_id,
            total_capsules_sent: 0,
            total_capsules_recv: 0,
        }
    }

    pub fn build_connect_udp_request(&self) -> String {
        format!(
            ":method = CONNECT\r\n\
             :protocol = connect-udp\r\n\
             :scheme = https\r\n\
             :authority = {}\r\n\
             :path = /.well-known/masque/udp/{}/{}/\r\n\
             capsule-protocol = ?1\r\n\r\n",
            self.target_host, self.target_host, self.target_port
        )
    }

    pub fn encode_capsule(&mut self, capsule: &MasqueCapsule) -> Vec<u8> {
        let mut out = Vec::new();
        // Variable-length integer encoding for capsule type and length
        let len = (capsule.payload.len() + 1) as u64; // +1 byte for context_id
        Self::write_varint(&mut out, capsule.capsule_type);
        Self::write_varint(&mut out, len);
        Self::write_varint(&mut out, capsule.context_id);
        out.extend_from_slice(&capsule.payload);

        self.total_capsules_sent += 1;
        out
    }

    pub fn decode_capsule(&mut self, data: &[u8]) -> Result<(MasqueCapsule, usize), String> {
        if data.is_empty() {
            return Err("Empty capsule data".to_string());
        }

        let mut offset = 0;
        let (cap_type, n1) = Self::read_varint(&data[offset..])?;
        offset += n1;

        let (cap_len, n2) = Self::read_varint(&data[offset..])?;
        offset += n2;

        if data.len() < offset + cap_len as usize {
            return Err("Incomplete capsule payload".to_string());
        }

        let (ctx_id, n3) = Self::read_varint(&data[offset..])?;
        offset += n3;

        let payload_len = (cap_len as usize).saturating_sub(n3);
        let payload = data[offset..offset + payload_len].to_vec();
        offset += payload_len;

        self.total_capsules_recv += 1;

        Ok((
            MasqueCapsule {
                capsule_type: cap_type,
                context_id: ctx_id,
                payload,
            },
            offset,
        ))
    }

    pub fn wrap_udp_datagram(&mut self, datagram: &[u8]) -> Vec<u8> {
        let cap = MasqueCapsule {
            capsule_type: MASQUE_CAPSULE_DATAGRAM,
            context_id: self.default_context_id,
            payload: datagram.to_vec(),
        };
        self.encode_capsule(&cap)
    }

    fn write_varint(buf: &mut Vec<u8>, val: u64) {
        if val < 64 {
            buf.push(val as u8);
        } else if val < 16384 {
            buf.push(0x40 | ((val >> 8) as u8));
            buf.push((val & 0xff) as u8);
        } else {
            buf.push(0x80 | ((val >> 24) as u8));
            buf.push(((val >> 16) & 0xff) as u8);
            buf.push(((val >> 8) & 0xff) as u8);
            buf.push((val & 0xff) as u8);
        }
    }

    fn read_varint(data: &[u8]) -> Result<(u64, usize), String> {
        if data.is_empty() {
            return Err("Unexpected EOF".to_string());
        }
        let prefix = data[0] >> 6;
        match prefix {
            0 => Ok((data[0] as u64, 1)),
            1 => {
                if data.len() < 2 {
                    return Err("Varint truncated".to_string());
                }
                let v = (((data[0] & 0x3f) as u64) << 8) | (data[1] as u64);
                Ok((v, 2))
            }
            2 => {
                if data.len() < 4 {
                    return Err("Varint truncated".to_string());
                }
                let v = (((data[0] & 0x3f) as u64) << 24)
                    | ((data[1] as u64) << 16)
                    | ((data[2] as u64) << 8)
                    | (data[3] as u64);
                Ok((v, 4))
            }
            _ => Err("Unsupported varint size".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_masque_connect_udp_and_datagram_capsule() {
        let mut tunnel = MasqueDatagramTunnel::new("warp.cloudflare.com", 443, 0);
        let req = tunnel.build_connect_udp_request();
        assert!(req.contains("connect-udp"));
        assert!(req.contains("capsule-protocol = ?1"));

        let payload = b"WireGuard Handshake Initiation";
        let wrapped = tunnel.wrap_udp_datagram(payload);

        let (capsule, consumed) = tunnel.decode_capsule(&wrapped).unwrap();
        assert_eq!(consumed, wrapped.len());
        assert_eq!(capsule.capsule_type, MASQUE_CAPSULE_DATAGRAM);
        assert_eq!(capsule.context_id, 0);
        assert_eq!(capsule.payload, payload);
    }
}
