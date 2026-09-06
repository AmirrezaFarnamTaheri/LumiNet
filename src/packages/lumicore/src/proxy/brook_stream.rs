//! # Brook Obfuscated Tunnel Protocol Stream Codec
//!
//! Encapsulates TCP/UDP proxy traffic with 8-byte randomized header padding,
//! command bytes, and variable-length destination address encoding.

pub const BROOK_CMD_TCP: u8 = 0x01;
pub const BROOK_CMD_UDP: u8 = 0x02;

pub const BROOK_ADDR_IPV4: u8 = 0x01;
pub const BROOK_ADDR_DOMAIN: u8 = 0x02;
pub const BROOK_ADDR_IPV6: u8 = 0x03;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrookTargetAddress {
    pub addr_type: u8,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrookRequest {
    pub random_padding: [u8; 8],
    pub command: u8,
    pub target: BrookTargetAddress,
    pub payload: Vec<u8>,
}

impl BrookRequest {
    pub fn new(command: u8, target: BrookTargetAddress, payload: Vec<u8>) -> Self {
        // Fast deterministic pseudo-random header for testing/reproducibility
        let mut random_padding = [0u8; 8];
        for i in 0..8 {
            random_padding[i] = ((i as u8).wrapping_mul(37)).wrapping_add(19);
        }
        Self {
            random_padding,
            command,
            target,
            payload,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.random_padding);
        buf.push(self.command);
        buf.push(self.target.addr_type);

        match self.target.addr_type {
            BROOK_ADDR_IPV4 => {
                let parts: Vec<u8> = self.target.host.split('.').filter_map(|p| p.parse::<u8>().ok()).collect();
                if parts.len() == 4 {
                    buf.extend_from_slice(&parts);
                } else {
                    buf.extend_from_slice(&[0, 0, 0, 0]);
                }
            }
            BROOK_ADDR_DOMAIN => {
                let bytes = self.target.host.as_bytes();
                buf.push(bytes.len() as u8);
                buf.extend_from_slice(bytes);
            }
            _ => {
                buf.push(0);
            }
        }

        buf.extend_from_slice(&self.target.port.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 10 {
            return Err("Brook packet too short");
        }
        let mut random_padding = [0u8; 8];
        random_padding.copy_from_slice(&bytes[0..8]);
        let command = bytes[8];
        let addr_type = bytes[9];

        let mut offset = 10;
        let host = match addr_type {
            BROOK_ADDR_IPV4 => {
                if bytes.len() < offset + 4 {
                    return Err("Truncated IPv4 in Brook header");
                }
                let h = format!("{}.{}.{}.{}", bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]);
                offset += 4;
                h
            }
            BROOK_ADDR_DOMAIN => {
                if bytes.len() < offset + 1 {
                    return Err("Truncated domain len in Brook header");
                }
                let len = bytes[offset] as usize;
                offset += 1;
                if bytes.len() < offset + len {
                    return Err("Truncated domain body in Brook header");
                }
                let h = String::from_utf8_lossy(&bytes[offset..offset + len]).to_string();
                offset += len;
                h
            }
            _ => return Err("Unsupported Brook address type"),
        };

        if bytes.len() < offset + 2 {
            return Err("Truncated port in Brook header");
        }
        let mut port_bytes = [0u8; 2];
        port_bytes.copy_from_slice(&bytes[offset..offset + 2]);
        let port = u16::from_be_bytes(port_bytes);
        offset += 2;

        let payload = bytes[offset..].to_vec();

        Ok(Self {
            random_padding,
            command,
            target: BrookTargetAddress { addr_type, host, port },
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_brook_codec_roundtrip() {
        let req = BrookRequest::new(
            BROOK_CMD_TCP,
            BrookTargetAddress {
                addr_type: BROOK_ADDR_DOMAIN,
                host: "api.target.com".to_string(),
                port: 443,
            },
            b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        );

        let serialized = req.serialize();
        let parsed = BrookRequest::deserialize(&serialized).unwrap();
        assert_eq!(parsed.command, BROOK_CMD_TCP);
        assert_eq!(parsed.target.host, "api.target.com");
        assert_eq!(parsed.target.port, 443);
        assert_eq!(parsed.payload, b"GET / HTTP/1.1\r\n\r\n");
    }
}
