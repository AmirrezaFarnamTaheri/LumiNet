//! # Pure-Rust VLESS Stream Protocol Codec
//!
//! Implements the VLESS client protocol wire encoding and decoding.
//! Ported and elevated from `tunl-main`.

use std::net::{Ipv4Addr, Ipv6Addr};

pub const VLESS_VERSION: u8 = 0;

/// VLESS command types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessCommand {
    Tcp = 1,
    Udp = 2,
    Mux = 3,
}

impl VlessCommand {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Tcp),
            2 => Some(Self::Udp),
            3 => Some(Self::Mux),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Target address formats supported by VLESS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VlessAddress {
    Ipv4(Ipv4Addr),
    Domain(String),
    Ipv6(Ipv6Addr),
}

/// VLESS client request header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessRequestHeader {
    pub version: u8,
    pub uuid: [u8; 16],
    pub command: VlessCommand,
    pub port: u16,
    pub address: VlessAddress,
    pub addons: Vec<u8>,
}

impl VlessRequestHeader {
    pub fn new_tcp(uuid: [u8; 16], port: u16, address: VlessAddress) -> Self {
        Self {
            version: VLESS_VERSION,
            uuid,
            command: VlessCommand::Tcp,
            port,
            address,
            addons: Vec::new(),
        }
    }

    pub fn new_udp(uuid: [u8; 16], port: u16, address: VlessAddress) -> Self {
        Self {
            version: VLESS_VERSION,
            uuid,
            command: VlessCommand::Udp,
            port,
            address,
            addons: Vec::new(),
        }
    }

    /// Serializes the request header into wire format bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        // 1. Version
        out.push(self.version);
        // 2. UUID
        out.extend_from_slice(&self.uuid);
        // 3. Addons length + data
        out.push(self.addons.len() as u8);
        out.extend_from_slice(&self.addons);
        // 4. Command
        out.push(self.command.to_u8());
        // 5. Port
        out.extend_from_slice(&self.port.to_be_bytes());
        // 6. Address
        match &self.address {
            VlessAddress::Ipv4(ip) => {
                out.push(0x01);
                out.extend_from_slice(&ip.octets());
            }
            VlessAddress::Domain(dom) => {
                out.push(0x02);
                out.push(dom.len() as u8);
                out.extend_from_slice(dom.as_bytes());
            }
            VlessAddress::Ipv6(ip) => {
                out.push(0x03);
                out.extend_from_slice(&ip.octets());
            }
        }
        out
    }

    /// Deserializes a request header from wire bytes.
    pub fn deserialize(buf: &[u8]) -> Result<(Self, usize), &'static str> {
        if buf.len() < 19 {
            return Err("Buffer too short for VLESS header");
        }

        let version = buf[0];
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buf[1..17]);

        let addons_len = buf[17] as usize;
        let mut cursor = 18 + addons_len;
        if buf.len() < cursor + 4 {
            return Err("Buffer too short for VLESS addons/command");
        }

        let addons = buf[18..cursor].to_vec();
        let command_byte = buf[cursor];
        cursor += 1;
        let command = VlessCommand::from_u8(command_byte).ok_or("Invalid VLESS command")?;

        let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
        cursor += 2;

        let addr_type = buf[cursor];
        cursor += 1;

        let address = match addr_type {
            0x01 => {
                if buf.len() < cursor + 4 {
                    return Err("Buffer too short for IPv4");
                }
                let mut octets = [0u8; 4];
                octets.copy_from_slice(&buf[cursor..cursor + 4]);
                cursor += 4;
                VlessAddress::Ipv4(Ipv4Addr::from(octets))
            }
            0x02 => {
                if buf.len() < cursor + 1 {
                    return Err("Buffer too short for domain length");
                }
                let domain_len = buf[cursor] as usize;
                cursor += 1;
                if buf.len() < cursor + domain_len {
                    return Err("Buffer too short for domain");
                }
                let domain_str = std::str::from_utf8(&buf[cursor..cursor + domain_len])
                    .map_err(|_| "Invalid UTF-8 domain")?;
                cursor += domain_len;
                VlessAddress::Domain(domain_str.to_string())
            }
            0x03 => {
                if buf.len() < cursor + 16 {
                    return Err("Buffer too short for IPv6");
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[cursor..cursor + 16]);
                cursor += 16;
                VlessAddress::Ipv6(Ipv6Addr::from(octets))
            }
            _ => return Err("Unsupported address type"),
        };

        Ok((
            Self {
                version,
                uuid,
                command,
                port,
                address,
                addons,
            },
            cursor,
        ))
    }
}

/// VLESS server response header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessResponseHeader {
    pub version: u8,
    pub addons: Vec<u8>,
}

impl VlessResponseHeader {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.addons.len());
        out.push(self.version);
        out.push(self.addons.len() as u8);
        out.extend_from_slice(&self.addons);
        out
    }

    pub fn deserialize(buf: &[u8]) -> Result<(Self, usize), &'static str> {
        if buf.len() < 2 {
            return Err("Buffer too short for response header");
        }
        let version = buf[0];
        let addons_len = buf[1] as usize;
        if buf.len() < 2 + addons_len {
            return Err("Buffer too short for response addons");
        }
        let addons = buf[2..2 + addons_len].to_vec();
        Ok((Self { version, addons }, 2 + addons_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vless_request_header_domain_roundtrip() {
        let uuid = [0x12; 16];
        let hdr = VlessRequestHeader::new_tcp(
            uuid,
            443,
            VlessAddress::Domain("example.com".to_string()),
        );

        let bytes = hdr.serialize();
        let (parsed, consumed) = VlessRequestHeader::deserialize(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed, hdr);
    }

    #[test]
    fn test_vless_request_header_ipv4_roundtrip() {
        let uuid = [0xab; 16];
        let hdr = VlessRequestHeader::new_udp(
            uuid,
            53,
            VlessAddress::Ipv4(Ipv4Addr::new(1, 1, 1, 1)),
        );

        let bytes = hdr.serialize();
        let (parsed, consumed) = VlessRequestHeader::deserialize(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed, hdr);
    }

    #[test]
    fn test_vless_response_header_roundtrip() {
        let resp = VlessResponseHeader {
            version: 0,
            addons: vec![0x01, 0x02],
        };
        let bytes = resp.serialize();
        let (parsed, consumed) = VlessResponseHeader::deserialize(&bytes).unwrap();
        assert_eq!(consumed, 4);
        assert_eq!(parsed, resp);
    }
}
