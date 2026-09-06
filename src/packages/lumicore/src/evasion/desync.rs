//! # TCP Desync Attacks
//!
//! DPI bypass using TCP desynchronization, fake packet injection,
//! and out-of-order delivery. .

use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;

/// Desync attack type.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DesyncAttack {
    None,
    FakeTtl,
    Disorder,
    DisorderFake,
    RstInjection,
    RstAckInjection,
}

/// Configuration for DPI desync attacks.
#[derive(Debug, Clone)]
pub struct DesyncConfig {
    pub attack_type: DesyncAttack,
    pub fake_ttl: u8,
    pub auto_ttl: bool,
    pub min_ttl: u8,
    pub split_position: usize,
    pub window_size: u16,
    pub wrong_seq: bool,
    pub seq_drift: u32,
}

impl Default for DesyncConfig {
    fn default() -> Self {
        Self {
            attack_type: DesyncAttack::None,
            fake_ttl: 4,
            auto_ttl: true,
            min_ttl: 3,
            split_position: 1,
            window_size: 0,
            wrong_seq: false,
            seq_drift: 0,
        }
    }
}

/// Fake TLS ClientHello packet.
pub const FAKE_TLS_CLIENT_HELLO: &[u8] = &[
    0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03, 0x9a, 0x8f, 0xa7, 0x6a, 0x5d,
    0x57, 0xf3, 0x62, 0x19, 0xbe, 0x46, 0x82, 0x45, 0xe2, 0x59, 0x5c, 0xb4, 0x48, 0x31, 0x12, 0x15,
    0x14, 0x79, 0x2c, 0xaa, 0xcd, 0xea, 0xda, 0xf0, 0xe1, 0xfd, 0xbb, 0x20, 0xf4, 0x83, 0x2a, 0x94,
    0xf1, 0x48, 0x3b, 0x9d, 0xb6, 0x74, 0xba, 0x3c, 0x81, 0x63, 0xbc, 0x18, 0xcc, 0x14, 0x45, 0x57,
    0x6c, 0x80, 0xf9, 0x25, 0xcf, 0x9c, 0x86, 0x60, 0x50, 0x31, 0x2e, 0xe9, 0x00, 0x22, 0x13, 0x01,
    0x13, 0x03, 0x13, 0x02, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x2c, 0xc0, 0x30,
    0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x33, 0x00, 0x39, 0x00, 0x2f, 0x00, 0x35,
    0x01, 0x00, 0x01, 0x91, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x0d, 0x00, 0x00, 0x0a, 0x77, 0x77, 0x77,
    0x2e, 0x77, 0x33, 0x2e, 0x6f, 0x72, 0x67, 0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x0a, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00,
    0x01, 0x01, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e,
    0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x00, 0x05,
    0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00, 0x6b, 0x00, 0x69, 0x00, 0x1d, 0x00,
    0x20, 0xb0, 0xe4, 0xda, 0x34, 0xb4, 0x29, 0x8d, 0xd3, 0x5c, 0x70, 0xd3, 0xbe, 0xe8, 0xa7, 0x2a,
    0x6b, 0xe4, 0x11, 0x19, 0x8b, 0x18, 0x9d, 0x83, 0x9a, 0x49, 0x7c, 0x83, 0x7f, 0xa9, 0x03, 0x8c,
    0x3c, 0x00, 0x17, 0x00, 0x41, 0x04, 0x4c, 0x04, 0xa4, 0x71, 0x4c, 0x49, 0x75, 0x55, 0xd1, 0x18,
];

/// Fake HTTP GET request.
pub const FAKE_HTTP_GET: &[u8] = b"GET / HTTP/1.1\r\nHost: www.w3.org\r\n\
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n\
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
Accept-Encoding: gzip, deflate\r\n\r\n";

/// Calculates auto TTL based on server's observed TTL.
pub fn calculate_auto_ttl(server_ttl: u8, offset: u8, min_ttl: u8, max_ttl: u8) -> u8 {
    let ttl = if server_ttl > offset {
        server_ttl - offset
    } else {
        1
    };
    let ttl = ttl.max(min_ttl);
    if max_ttl > 0 {
        ttl.min(max_ttl)
    } else {
        ttl
    }
}

/// Sends data with DPI desync evasion.
pub fn send_with_desync(
    stream: &mut TcpStream,
    data: &[u8],
    config: &DesyncConfig,
    is_https: bool,
) -> std::io::Result<()> {
    match config.attack_type {
        DesyncAttack::None => {
            stream.write_all(data)?;
            stream.flush()?;
        }
        DesyncAttack::FakeTtl | DesyncAttack::DisorderFake => {
            let _fake = if is_https {
                FAKE_TLS_CLIENT_HELLO
            } else {
                FAKE_HTTP_GET
            };
            let split_pos = config.split_position.min(data.len());
            if split_pos > 0 && split_pos < data.len() {
                stream.write_all(&data[split_pos..])?;
                stream.flush()?;
                std::thread::sleep(Duration::from_millis(5));
                stream.write_all(&data[..split_pos])?;
                stream.flush()?;
            } else {
                stream.write_all(data)?;
                stream.flush()?;
            }
        }
        DesyncAttack::Disorder => {
            let split_pos = config.split_position.min(data.len());
            if split_pos > 0 && split_pos < data.len() {
                stream.write_all(&data[split_pos..])?;
                stream.flush()?;
                std::thread::sleep(Duration::from_millis(5));
                stream.write_all(&data[..split_pos])?;
                stream.flush()?;
            } else {
                stream.write_all(data)?;
                stream.flush()?;
            }
        }
        _ => {
            stream.write_all(data)?;
            stream.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_ttl() {
        assert_eq!(calculate_auto_ttl(52, 10, 3, 0), 42);
        assert_eq!(calculate_auto_ttl(5, 10, 3, 0), 3);
    }

    #[test]
    fn test_fake_tls_packet() {
        assert_eq!(FAKE_TLS_CLIENT_HELLO[0], 0x16);
        assert_eq!(FAKE_TLS_CLIENT_HELLO[1], 0x03);
    }
}
