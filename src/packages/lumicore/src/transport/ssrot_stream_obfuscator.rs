//! # SSRoT Stream Obfuscator
//!
//! Native ShadowsocksR / SSRoT stream obfuscator implementing protocol plugins
//! and dynamic obfs wrapping (Plain, HttpSimple, Tls12TicketAuth).

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsrotObfsType {
    Plain,
    HttpSimple,
    Tls12TicketAuth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsrotProtocolType {
    Origin,
    AuthSha1V4,
    AuthAes128Md5,
    AuthChainA,
}

#[derive(Debug, Clone)]
pub struct SsrotConfig {
    pub password: String,
    pub protocol: SsrotProtocolType,
    pub obfs: SsrotObfsType,
    pub obfs_param: String,
}

pub struct SsrotStreamObfuscator {
    config: SsrotConfig,
    send_id: u32,
    recv_id: u32,
    secret_key: Vec<u8>,
}

impl SsrotStreamObfuscator {
    pub fn new(config: SsrotConfig) -> Self {
        let digest = md5::compute(config.password.as_bytes());
        let secret_key = digest.0.to_vec();

        Self {
            config,
            send_id: 1,
            recv_id: 1,
            secret_key,
        }
    }

    pub fn client_encode_handshake(&mut self, target_host: &str, target_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut raw = Vec::new();
        let host_bytes = target_host.as_bytes();
        
        // Target address header: [atyp = 3 (domain)][len][host][port_be]
        raw.push(3u8);
        raw.push(host_bytes.len() as u8);
        raw.extend_from_slice(host_bytes);
        raw.extend_from_slice(&target_port.to_be_bytes());
        raw.extend_from_slice(payload);

        // Protocol transformation
        let proto_wrapped = self.wrap_protocol(&raw);

        // Obfuscation transformation
        self.wrap_obfs(&proto_wrapped)
    }

    pub fn server_decode_handshake(&mut self, data: &[u8]) -> Result<(String, u16, Vec<u8>), String> {
        let unwrapped_obfs = self.unwrap_obfs(data)?;
        let unwrapped_proto = self.unwrap_protocol(&unwrapped_obfs)?;

        if unwrapped_proto.len() < 4 {
            return Err("Handshake data too short".to_string());
        }

        let atyp = unwrapped_proto[0];
        if atyp != 3 {
            return Err(format!("Unsupported atyp: {}", atyp));
        }

        let host_len = unwrapped_proto[1] as usize;
        if unwrapped_proto.len() < 2 + host_len + 2 {
            return Err("Incomplete host/port in handshake".to_string());
        }

        let host = String::from_utf8_lossy(&unwrapped_proto[2..2 + host_len]).to_string();
        let port_bytes = [unwrapped_proto[2 + host_len], unwrapped_proto[3 + host_len]];
        let port = u16::from_be_bytes(port_bytes);
        let payload = unwrapped_proto[4 + host_len..].to_vec();

        Ok((host, port, payload))
    }

    pub fn encode_chunk(&mut self, data: &[u8]) -> Vec<u8> {
        self.send_id = self.send_id.wrapping_add(1);
        let len_be = (data.len() as u16).to_be_bytes();
        let mut chunk = Vec::with_capacity(2 + 4 + data.len() + 4);
        chunk.extend_from_slice(&len_be);
        chunk.extend_from_slice(&self.send_id.to_be_bytes());
        
        // Add XOR mask using secret_key
        for (i, byte) in data.iter().enumerate() {
            let key_byte = self.secret_key[i % self.secret_key.len()];
            chunk.push(byte ^ key_byte);
        }

        // 4-byte CRC/HMAC tag
        let mut mac = HmacSha256::new_from_slice(&self.secret_key).expect("Valid key");
        mac.update(&chunk);
        let tag = mac.finalize().into_bytes();
        chunk.extend_from_slice(&tag[..4]);

        chunk
    }

    pub fn decode_chunk(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 10 {
            return Err("Chunk too small".to_string());
        }

        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 6 + len + 4 {
            return Err("Incomplete chunk data".to_string());
        }

        let recv_id = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
        self.recv_id = recv_id;

        // Verify tag
        let mut mac = HmacSha256::new_from_slice(&self.secret_key).expect("Valid key");
        mac.update(&data[..6 + len]);
        let tag = mac.finalize().into_bytes();
        if &tag[..4] != &data[6 + len..6 + len + 4] {
            return Err("Invalid chunk HMAC tag".to_string());
        }

        // Unmask
        let mut unmasked = Vec::with_capacity(len);
        for (i, byte) in data[6..6 + len].iter().enumerate() {
            let key_byte = self.secret_key[i % self.secret_key.len()];
            unmasked.push(byte ^ key_byte);
        }

        Ok(unmasked)
    }

    fn wrap_protocol(&self, data: &[u8]) -> Vec<u8> {
        match self.config.protocol {
            SsrotProtocolType::Origin => data.to_vec(),
            SsrotProtocolType::AuthSha1V4 | SsrotProtocolType::AuthAes128Md5 | SsrotProtocolType::AuthChainA => {
                let mut out = Vec::with_capacity(data.len() + 10);
                out.extend_from_slice(b"SSR");
                out.push(1u8); // Version
                let mut mac = HmacSha1::new_from_slice(&self.secret_key).expect("Valid key");
                mac.update(data);
                let tag = mac.finalize().into_bytes();
                out.extend_from_slice(&tag[..4]);
                out.extend_from_slice(data);
                out
            }
        }
    }

    fn unwrap_protocol(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        match self.config.protocol {
            SsrotProtocolType::Origin => Ok(data.to_vec()),
            SsrotProtocolType::AuthSha1V4 | SsrotProtocolType::AuthAes128Md5 | SsrotProtocolType::AuthChainA => {
                if data.len() < 8 || &data[..3] != b"SSR" {
                    return Err("Invalid protocol header".to_string());
                }
                let payload = &data[8..];
                let mut mac = HmacSha1::new_from_slice(&self.secret_key).expect("Valid key");
                mac.update(payload);
                let tag = mac.finalize().into_bytes();
                if &tag[..4] != &data[4..8] {
                    return Err("Protocol HMAC verification failed".to_string());
                }
                Ok(payload.to_vec())
            }
        }
    }

    fn wrap_obfs(&self, data: &[u8]) -> Vec<u8> {
        match self.config.obfs {
            SsrotObfsType::Plain => data.to_vec(),
            SsrotObfsType::HttpSimple => {
                let host = if self.config.obfs_param.is_empty() {
                    "cloudflare.com"
                } else {
                    &self.config.obfs_param
                };
                let header = format!(
                    "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nContent-Length: {}\r\n\r\n",
                    host,
                    data.len()
                );
                let mut out = header.into_bytes();
                out.extend_from_slice(data);
                out
            }
            SsrotObfsType::Tls12TicketAuth => {
                let mut out = Vec::with_capacity(data.len() + 5);
                out.push(0x16); // TLS Handshake
                out.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
                let len_be = (data.len() as u16).to_be_bytes();
                out.extend_from_slice(&len_be);
                out.extend_from_slice(data);
                out
            }
        }
    }

    fn unwrap_obfs(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        match self.config.obfs {
            SsrotObfsType::Plain => Ok(data.to_vec()),
            SsrotObfsType::HttpSimple => {
                let delim = b"\r\n\r\n";
                if let Some(pos) = data.windows(4).position(|w| w == delim) {
                    Ok(data[pos + 4..].to_vec())
                } else {
                    Err("Invalid HTTP simple obfuscation framing".to_string())
                }
            }
            SsrotObfsType::Tls12TicketAuth => {
                if data.len() < 5 || data[0] != 0x16 {
                    return Err("Invalid TLS ticket auth framing".to_string());
                }
                let len = u16::from_be_bytes([data[3], data[4]]) as usize;
                if data.len() < 5 + len {
                    return Err("Incomplete TLS record payload".to_string());
                }
                Ok(data[5..5 + len].to_vec())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plain_origin_handshake_and_chunk() {
        let config = SsrotConfig {
            password: "mypassword123".to_string(),
            protocol: SsrotProtocolType::Origin,
            obfs: SsrotObfsType::Plain,
            obfs_param: "".to_string(),
        };

        let mut client = SsrotStreamObfuscator::new(config.clone());
        let mut server = SsrotStreamObfuscator::new(config);

        let handshake = client.client_encode_handshake("example.com", 443, b"ping");
        let (host, port, payload) = server.server_decode_handshake(&handshake).unwrap();

        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(payload, b"ping");

        let chunk = client.encode_chunk(b"hello world");
        let decoded = server.decode_chunk(&chunk).unwrap();
        assert_eq!(decoded, b"hello world");
    }

    #[test]
    fn test_auth_sha1_http_simple() {
        let config = SsrotConfig {
            password: "anotherpassword".to_string(),
            protocol: SsrotProtocolType::AuthSha1V4,
            obfs: SsrotObfsType::HttpSimple,
            obfs_param: "myproxy.org".to_string(),
        };

        let mut client = SsrotStreamObfuscator::new(config.clone());
        let mut server = SsrotStreamObfuscator::new(config);

        let handshake = client.client_encode_handshake("api.service.internal", 8080, b"data123");
        let (host, port, payload) = server.server_decode_handshake(&handshake).unwrap();

        assert_eq!(host, "api.service.internal");
        assert_eq!(port, 8080);
        assert_eq!(payload, b"data123");
    }

    #[test]
    fn test_tls12_ticket_auth_chunking() {
        let config = SsrotConfig {
            password: "secret_session_key".to_string(),
            protocol: SsrotProtocolType::AuthChainA,
            obfs: SsrotObfsType::Tls12TicketAuth,
            obfs_param: "".to_string(),
        };

        let mut client = SsrotStreamObfuscator::new(config.clone());
        let mut server = SsrotStreamObfuscator::new(config);

        let handshake = client.client_encode_handshake("secure.portal", 8443, b"init");
        let (host, port, payload) = server.server_decode_handshake(&handshake).unwrap();

        assert_eq!(host, "secure.portal");
        assert_eq!(port, 8443);
        assert_eq!(payload, b"init");
    }
}
