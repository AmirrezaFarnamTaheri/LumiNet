//! Edge Serverless WebSocket Protocol Codec for VLESS and Trojan.
//!
//! Provides binary protocol framing for Cloudflare Worker and edge proxy environments:
//! 1. VLESS-over-WebSocket:
//!    - Version 0x00, 16-byte UUID authentication.
//!    - Command parsing: 0x01 (TCP CONNECT), 0x02 (UDP / DNS).
//!    - Address decoding: 0x01 (IPv4), 0x02 (Domain length-prefixed), 0x03 (IPv6).
//!    - Response header construction: `[version, 0x00]`.
//!    - Base64 URL-safe early data extraction (`sec-websocket-protocol`).
//! 2. Trojan-over-WebSocket:
//!    - 56-byte hexadecimal SHA-224 password digest authentication.
//!    - CRLF (`0x0D, 0x0A`) protocol boundary verification.
//!    - SOCKS5 address type decoding (0x01 IPv4, 0x03 Domain, 0x04 IPv6).
//!    - Raw client payload extraction.

use sha2::{Digest, Sha224};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Supported destination address types in VLESS and Trojan frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddress {
    Ipv4(Ipv4Addr),
    Domain(String),
    Ipv6(Ipv6Addr),
}

/// Parsed VLESS frame header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessWsHeader {
    pub version: u8,
    pub user_uuid: [u8; 16],
    pub is_udp: bool,
    pub target_addr: TargetAddress,
    pub target_port: u16,
    pub payload_offset: usize,
}

/// Errors occurring during edge WebSocket protocol parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeCodecError {
    BufferTooShort,
    InvalidVersion(u8),
    InvalidUser,
    UnsupportedCommand(u8),
    InvalidAddressType(u8),
    EmptyAddress,
    MissingCrLfDelimiter,
    InvalidPasswordHash,
    InvalidEarlyData,
}

/// Parses an incoming binary VLESS frame over WebSocket.
pub fn parse_vless_ws_header(
    buffer: &[u8],
    expected_uuid: &[u8; 16],
) -> Result<VlessWsHeader, EdgeCodecError> {
    if buffer.len() < 24 {
        return Err(EdgeCodecError::BufferTooShort);
    }

    let version = buffer[0];
    let user_uuid = &buffer[1..17];
    if user_uuid != expected_uuid {
        return Err(EdgeCodecError::InvalidUser);
    }

    let opt_len = buffer[17] as usize;
    let cmd_index = 18 + opt_len;
    if buffer.len() <= cmd_index {
        return Err(EdgeCodecError::BufferTooShort);
    }

    let command = buffer[cmd_index];
    let is_udp = match command {
        0x01 => false, // TCP
        0x02 => true,  // UDP (DNS)
        _ => return Err(EdgeCodecError::UnsupportedCommand(command)),
    };

    let port_index = cmd_index + 1;
    if buffer.len() < port_index + 2 {
        return Err(EdgeCodecError::BufferTooShort);
    }
    let target_port = u16::from_be_bytes([buffer[port_index], buffer[port_index + 1]]);

    let addr_index = port_index + 2;
    if buffer.len() <= addr_index {
        return Err(EdgeCodecError::BufferTooShort);
    }
    let addr_type = buffer[addr_index];
    let val_index = addr_index + 1;

    let (target_addr, next_index) = match addr_type {
        0x01 => {
            // IPv4: 4 bytes
            if buffer.len() < val_index + 4 {
                return Err(EdgeCodecError::BufferTooShort);
            }
            let octets: [u8; 4] = [
                buffer[val_index],
                buffer[val_index + 1],
                buffer[val_index + 2],
                buffer[val_index + 3],
            ];
            (TargetAddress::Ipv4(Ipv4Addr::from(octets)), val_index + 4)
        }
        0x02 => {
            // Domain: 1 byte length prefix + ASCII string
            if buffer.len() <= val_index {
                return Err(EdgeCodecError::BufferTooShort);
            }
            let dlen = buffer[val_index] as usize;
            let str_start = val_index + 1;
            if buffer.len() < str_start + dlen {
                return Err(EdgeCodecError::BufferTooShort);
            }
            let domain_str = String::from_utf8_lossy(&buffer[str_start..str_start + dlen]).to_string();
            if domain_str.is_empty() {
                return Err(EdgeCodecError::EmptyAddress);
            }
            (TargetAddress::Domain(domain_str), str_start + dlen)
        }
        0x03 => {
            // IPv6: 16 bytes
            if buffer.len() < val_index + 16 {
                return Err(EdgeCodecError::BufferTooShort);
            }
            let mut segs = [0u8; 16];
            segs.copy_from_slice(&buffer[val_index..val_index + 16]);
            (TargetAddress::Ipv6(Ipv6Addr::from(segs)), val_index + 16)
        }
        _ => return Err(EdgeCodecError::InvalidAddressType(addr_type)),
    };

    let mut uuid_arr = [0u8; 16];
    uuid_arr.copy_from_slice(user_uuid);

    Ok(VlessWsHeader {
        version,
        user_uuid: uuid_arr,
        is_udp,
        target_addr,
        target_port,
        payload_offset: next_index,
    })
}

/// Constructs the standard VLESS response header: `[version, 0x00]`.
pub fn build_vless_response_header(version: u8) -> [u8; 2] {
    [version, 0x00]
}

/// Parsed Trojan frame header over WebSocket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanWsHeader {
    pub target_addr: TargetAddress,
    pub target_port: u16,
    pub payload_offset: usize,
}

/// Computes the standard 56-byte SHA-224 hexadecimal password hash for Trojan.
pub fn compute_trojan_sha224_hash(password: &str) -> String {
    let mut hasher = Sha224::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    format!("{result:x}")
}

/// Parses an incoming binary Trojan frame over WebSocket.
pub fn parse_trojan_ws_header(
    buffer: &[u8],
    expected_sha224_hex: &str,
) -> Result<TrojanWsHeader, EdgeCodecError> {
    if buffer.len() < 58 {
        return Err(EdgeCodecError::BufferTooShort);
    }

    // Bytes 0..56: SHA-224 password digest in ASCII hexadecimal
    let pass_slice = &buffer[0..56];
    let received_hash = String::from_utf8_lossy(pass_slice);
    if !received_hash.eq_ignore_ascii_case(expected_sha224_hex) {
        return Err(EdgeCodecError::InvalidPasswordHash);
    }

    // Bytes 56..58: CRLF delimiter (0x0D, 0x0A)
    if buffer[56] != 0x0d || buffer[57] != 0x0a {
        return Err(EdgeCodecError::MissingCrLfDelimiter);
    }

    let socks5 = &buffer[58..];
    if socks5.len() < 6 {
        return Err(EdgeCodecError::BufferTooShort);
    }

    let cmd = socks5[0];
    if cmd != 0x01 {
        // Only TCP CONNECT is supported in Trojan over WS
        return Err(EdgeCodecError::UnsupportedCommand(cmd));
    }

    let atype = socks5[1];
    let mut addr_idx = 2;

    let (target_addr, port_idx) = match atype {
        0x01 => {
            // IPv4: 4 bytes
            if socks5.len() < addr_idx + 4 {
                return Err(EdgeCodecError::BufferTooShort);
            }
            let octets = [
                socks5[addr_idx],
                socks5[addr_idx + 1],
                socks5[addr_idx + 2],
                socks5[addr_idx + 3],
            ];
            (TargetAddress::Ipv4(Ipv4Addr::from(octets)), addr_idx + 4)
        }
        0x03 => {
            // Domain: 1 byte length prefix + ASCII string
            let dlen = socks5[addr_idx] as usize;
            addr_idx += 1;
            if socks5.len() < addr_idx + dlen {
                return Err(EdgeCodecError::BufferTooShort);
            }
            let domain_str = String::from_utf8_lossy(&socks5[addr_idx..addr_idx + dlen]).to_string();
            if domain_str.is_empty() {
                return Err(EdgeCodecError::EmptyAddress);
            }
            (TargetAddress::Domain(domain_str), addr_idx + dlen)
        }
        0x04 => {
            // IPv6: 16 bytes
            if socks5.len() < addr_idx + 16 {
                return Err(EdgeCodecError::BufferTooShort);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&socks5[addr_idx..addr_idx + 16]);
            (TargetAddress::Ipv6(Ipv6Addr::from(octets)), addr_idx + 16)
        }
        _ => return Err(EdgeCodecError::InvalidAddressType(atype)),
    };

    if socks5.len() < port_idx + 4 {
        return Err(EdgeCodecError::BufferTooShort);
    }
    let target_port = u16::from_be_bytes([socks5[port_idx], socks5[port_idx + 1]]);

    // SOCKS5 request ends with CRLF at port_idx+2, payload starts at port_idx+4
    let payload_offset = 58 + port_idx + 4;

    Ok(TrojanWsHeader {
        target_addr,
        target_port,
        payload_offset,
    })
}

/// Decodes base64 URL-safe early data header from WebSocket protocol handshakes.
pub fn decode_early_data(early_data_header: &str) -> Result<Vec<u8>, EdgeCodecError> {
    if early_data_header.is_empty() {
        return Ok(Vec::new());
    }

    // Translate URL-safe characters '-' -> '+', '_' -> '/'
    let mut normalized = early_data_header.replace('-', "+").replace('_', "/");
    while normalized.len() % 4 != 0 {
        normalized.push('=');
    }

    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(normalized.as_bytes())
        .map_err(|_| EdgeCodecError::InvalidEarlyData)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vless_header_parsing_ipv4() {
        let expected_uuid = [0xabu8; 16];
        let mut buf = Vec::new();
        buf.push(0x00); // version
        buf.extend_from_slice(&expected_uuid); // 16-byte UUID
        buf.push(0x00); // opt_len = 0
        buf.push(0x01); // cmd = 1 (TCP)
        buf.extend_from_slice(&443u16.to_be_bytes()); // port 443
        buf.push(0x01); // addr_type = IPv4
        buf.extend_from_slice(&[198, 51, 100, 1]); // 198.51.100.1
        buf.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n"); // payload

        let parsed = parse_vless_ws_header(&buf, &expected_uuid).unwrap();
        assert_eq!(parsed.version, 0x00);
        assert_eq!(parsed.target_port, 443);
        assert_eq!(parsed.target_addr, TargetAddress::Ipv4(Ipv4Addr::new(198, 51, 100, 1)));
        assert_eq!(&buf[parsed.payload_offset..], b"GET / HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn test_vless_header_parsing_domain() {
        let expected_uuid = [0x01u8; 16];
        let mut buf = Vec::new();
        buf.push(0x00);
        buf.extend_from_slice(&expected_uuid);
        buf.push(0x00);
        buf.push(0x01);
        buf.extend_from_slice(&80u16.to_be_bytes());
        buf.push(0x02); // Domain
        let domain = b"example.com";
        buf.push(domain.len() as u8);
        buf.extend_from_slice(domain);
        buf.extend_from_slice(b"PAYLOAD");

        let parsed = parse_vless_ws_header(&buf, &expected_uuid).unwrap();
        assert_eq!(parsed.target_addr, TargetAddress::Domain("example.com".to_string()));
        assert_eq!(parsed.target_port, 80);
        assert_eq!(&buf[parsed.payload_offset..], b"PAYLOAD");
    }

    #[test]
    fn test_trojan_header_parsing() {
        let pass = "my-secret-trojan-password";
        let hash = compute_trojan_sha224_hash(pass);

        let mut buf = Vec::new();
        buf.extend_from_slice(hash.as_bytes()); // 56 bytes
        buf.extend_from_slice(&[0x0d, 0x0a]); // CRLF

        // SOCKS5 request
        buf.push(0x01); // CONNECT
        buf.push(0x01); // IPv4
        buf.extend_from_slice(&[1, 1, 1, 1]); // 1.1.1.1
        buf.extend_from_slice(&53u16.to_be_bytes()); // port 53
        buf.extend_from_slice(&[0x0d, 0x0a]); // CRLF after port
        buf.extend_from_slice(b"DNS_QUERY_PAYLOAD");

        let parsed = parse_trojan_ws_header(&buf, &hash).unwrap();
        assert_eq!(parsed.target_addr, TargetAddress::Ipv4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(parsed.target_port, 53);
        assert_eq!(&buf[parsed.payload_offset..], b"DNS_QUERY_PAYLOAD");
    }

    #[test]
    fn test_early_data_decoding() {
        let raw = b"hello early data";
        use base64::Engine;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let decoded = decode_early_data(&encoded).unwrap();
        assert_eq!(decoded, raw);
    }
}
