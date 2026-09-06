//! Mixed Protocol Inbound Proxy Demultiplexer & Framer
//!
//! Ported and unified from `proxy-main`.
//! Provides single-port multiplexing for HTTP, HTTPS CONNECT, SOCKS4, SOCKS4a, SOCKS5, and SOCKS5h
//! by inspecting the initial wire handshake bytes, parsing target endpoints, and constructing compliant replies.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Inbound proxy protocol classification determined from the opening byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocolKind {
    /// SOCKS5 or SOCKS5h protocol (leading byte 0x05).
    Socks5,
    /// SOCKS4 or SOCKS4a protocol (leading byte 0x04).
    Socks4,
    /// HTTP / HTTPS CONNECT proxy (ASCII characters such as 'C', 'G', 'P', 'H').
    Http,
}

/// Detects the target proxy protocol from the initial byte received.
pub fn detect_proxy_protocol(first_byte: u8) -> ProxyProtocolKind {
    match first_byte {
        0x05 => ProxyProtocolKind::Socks5,
        0x04 => ProxyProtocolKind::Socks4,
        _ => ProxyProtocolKind::Http,
    }
}

// ---------------------------------------------------------------------------
// SOCKS4 / SOCKS4a Types & Framing
// ---------------------------------------------------------------------------

pub const SOCKS4_VERSION: u8 = 0x04;
pub const SOCKS4_CMD_CONNECT: u8 = 0x01;
pub const SOCKS4_CMD_BIND: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks4ReplyStatus {
    Granted = 0x5a,
    Rejected = 0x5b,
    NoIdentd = 0x5c,
    InvalidUser = 0x5d,
}

impl Socks4ReplyStatus {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x5a => Some(Self::Granted),
            0x5b => Some(Self::Rejected),
            0x5c => Some(Self::NoIdentd),
            0x5d => Some(Self::InvalidUser),
            _ => None,
        }
    }
}

/// Parsed SOCKS4 / SOCKS4a connection request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks4Request {
    pub command: u8,
    pub port: u16,
    pub ip: Ipv4Addr,
    pub user_id: String,
    pub domain: Option<String>,
}

impl Socks4Request {
    /// Returns the effective target host string (domain if SOCKS4a, otherwise IPv4 string).
    pub fn target_host(&self) -> String {
        if let Some(ref d) = self.domain {
            d.clone()
        } else {
            self.ip.to_string()
        }
    }

    /// Checks if this request is SOCKS4a (IP is 0.0.0.x with x != 0).
    pub fn is_socks4a(&self) -> bool {
        let octets = self.ip.octets();
        octets[0] == 0 && octets[1] == 0 && octets[2] == 0 && octets[3] != 0
    }
}

// ---------------------------------------------------------------------------
// SOCKS5 Types & Framing
// ---------------------------------------------------------------------------

pub const SOCKS5_VERSION: u8 = 0x05;
pub const SOCKS5_AUTH_NONE: u8 = 0x00;
pub const SOCKS5_AUTH_NO_ACCEPTABLE: u8 = 0xff;

pub const SOCKS5_CMD_CONNECT: u8 = 0x01;
pub const SOCKS5_CMD_BIND: u8 = 0x02;
pub const SOCKS5_CMD_UDP_ASSOCIATE: u8 = 0x03;

pub const SOCKS5_ATYP_IPV4: u8 = 0x01;
pub const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
pub const SOCKS5_ATYP_IPV6: u8 = 0x04;

pub const SOCKS5_REP_SUCCESS: u8 = 0x00;
pub const SOCKS5_REP_GENERAL_FAILURE: u8 = 0x01;
pub const SOCKS5_REP_CONNECTION_NOT_ALLOWED: u8 = 0x02;
pub const SOCKS5_REP_NETWORK_UNREACHABLE: u8 = 0x03;
pub const SOCKS5_REP_HOST_UNREACHABLE: u8 = 0x04;
pub const SOCKS5_REP_CONNECTION_REFUSED: u8 = 0x05;
pub const SOCKS5_REP_TTL_EXPIRED: u8 = 0x06;
pub const SOCKS5_REP_CMD_NOT_SUPPORTED: u8 = 0x07;
pub const SOCKS5_REP_ADDR_NOT_SUPPORTED: u8 = 0x08;

/// Parsed SOCKS5 greeting negotiation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Greeting {
    pub methods: Vec<u8>,
}

/// Parsed SOCKS5 connection command request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Request {
    pub command: u8,
    pub target_host: String,
    pub target_port: u16,
    pub address_type: u8,
}

// ---------------------------------------------------------------------------
// HTTP / HTTPS CONNECT Types & Framing
// ---------------------------------------------------------------------------

/// Parsed HTTP proxy or HTTPS CONNECT request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpProxyRequest {
    pub method: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub is_connect: bool,
}

// ---------------------------------------------------------------------------
// Unified Demux Request
// ---------------------------------------------------------------------------

/// Standardized cross-protocol connection request produced by the mixed demuxer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyDemuxRequest {
    pub protocol: ProxyProtocolKind,
    pub target_host: String,
    pub target_port: u16,
    pub is_udp: bool,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum MixedProxyError {
    BufferTooShort,
    InvalidProtocolVersion { expected: u8, got: u8 },
    InvalidCommand(u8),
    InvalidAddressType(u8),
    MalformedHttpHeader,
    MissingNullTerminator,
    MalformedDomain,
}

impl fmt::Display for MixedProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort => write!(f, "Buffer too short for parsing frame"),
            Self::InvalidProtocolVersion { expected, got } => {
                write!(f, "Invalid protocol version: expected 0x{:02x}, got 0x{:02x}", expected, got)
            }
            Self::InvalidCommand(c) => write!(f, "Invalid proxy command: 0x{:02x}", c),
            Self::InvalidAddressType(a) => write!(f, "Invalid SOCKS5 address type: 0x{:02x}", a),
            Self::MalformedHttpHeader => write!(f, "Malformed HTTP request header"),
            Self::MissingNullTerminator => write!(f, "Missing expected null terminator in string"),
            Self::MalformedDomain => write!(f, "Malformed domain string"),
        }
    }
}

impl std::error::Error for MixedProxyError {}

// ---------------------------------------------------------------------------
// Codec & Parser Implementation
// ---------------------------------------------------------------------------

pub struct MixedProtocolCodec;

impl MixedProtocolCodec {
    /// Parses a SOCKS4 or SOCKS4a request frame.
    /// Format: [0x04, CMD, PORT(2B), IP(4B), USERID..., 0x00, (OPTIONAL DOMAIN..., 0x00)]
    pub fn parse_socks4_request(buf: &[u8]) -> Result<(Socks4Request, usize), MixedProxyError> {
        if buf.len() < 8 {
            return Err(MixedProxyError::BufferTooShort);
        }
        if buf[0] != SOCKS4_VERSION {
            return Err(MixedProxyError::InvalidProtocolVersion {
                expected: SOCKS4_VERSION,
                got: buf[0],
            });
        }

        let command = buf[1];
        let port = u16::from_be_bytes([buf[2], buf[3]]);
        let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);

        let is_4a = buf[4] == 0 && buf[5] == 0 && buf[6] == 0 && buf[7] != 0;

        // Find null terminator for userid
        let mut idx = 8;
        while idx < buf.len() && buf[idx] != 0 {
            idx += 1;
        }
        if idx >= buf.len() {
            return Err(MixedProxyError::BufferTooShort);
        }
        let user_id = String::from_utf8_lossy(&buf[8..idx]).to_string();
        idx += 1; // Skip null

        let mut domain = None;
        if is_4a {
            let domain_start = idx;
            while idx < buf.len() && buf[idx] != 0 {
                idx += 1;
            }
            if idx >= buf.len() {
                return Err(MixedProxyError::BufferTooShort);
            }
            domain = Some(String::from_utf8_lossy(&buf[domain_start..idx]).to_string());
            idx += 1; // Skip null
        }

        Ok((
            Socks4Request {
                command,
                port,
                ip,
                user_id,
                domain,
            },
            idx,
        ))
    }

    /// Builds standard 8-byte SOCKS4 reply.
    /// Format: [0x00, STATUS, PORT(2B), IP(4B)]
    pub fn build_socks4_reply(
        status: Socks4ReplyStatus,
        bnd_port: u16,
        bnd_ip: [u8; 4],
    ) -> [u8; 8] {
        let port_bytes = bnd_port.to_be_bytes();
        [
            0x00,
            status.as_u8(),
            port_bytes[0],
            port_bytes[1],
            bnd_ip[0],
            bnd_ip[1],
            bnd_ip[2],
            bnd_ip[3],
        ]
    }

    /// Parses SOCKS5 greeting method negotiation request.
    /// Format: [0x05, NMETHODS, METHODS...]
    pub fn parse_socks5_greeting(buf: &[u8]) -> Result<(Socks5Greeting, usize), MixedProxyError> {
        if buf.len() < 2 {
            return Err(MixedProxyError::BufferTooShort);
        }
        if buf[0] != SOCKS5_VERSION {
            return Err(MixedProxyError::InvalidProtocolVersion {
                expected: SOCKS5_VERSION,
                got: buf[0],
            });
        }
        let nmethods = buf[1] as usize;
        let total_len = 2 + nmethods;
        if buf.len() < total_len {
            return Err(MixedProxyError::BufferTooShort);
        }
        let methods = buf[2..total_len].to_vec();
        Ok((Socks5Greeting { methods }, total_len))
    }

    /// Builds SOCKS5 greeting reply frame.
    /// Format: [0x05, METHOD]
    pub fn build_socks5_greeting_reply(method: u8) -> [u8; 2] {
        [SOCKS5_VERSION, method]
    }

    /// Parses SOCKS5 command request.
    /// Format: [0x05, CMD, 0x00, ATYP, ADDR..., PORT(2B)]
    pub fn parse_socks5_request(buf: &[u8]) -> Result<(Socks5Request, usize), MixedProxyError> {
        if buf.len() < 4 {
            return Err(MixedProxyError::BufferTooShort);
        }
        if buf[0] != SOCKS5_VERSION {
            return Err(MixedProxyError::InvalidProtocolVersion {
                expected: SOCKS5_VERSION,
                got: buf[0],
            });
        }

        let command = buf[1];
        let atyp = buf[3];
        let mut idx = 4;

        let target_host = match atyp {
            SOCKS5_ATYP_IPV4 => {
                if buf.len() < idx + 4 + 2 {
                    return Err(MixedProxyError::BufferTooShort);
                }
                let ip = Ipv4Addr::new(buf[idx], buf[idx + 1], buf[idx + 2], buf[idx + 3]);
                idx += 4;
                ip.to_string()
            }
            SOCKS5_ATYP_DOMAIN => {
                if buf.len() < idx + 1 {
                    return Err(MixedProxyError::BufferTooShort);
                }
                let dlen = buf[idx] as usize;
                idx += 1;
                if buf.len() < idx + dlen + 2 {
                    return Err(MixedProxyError::BufferTooShort);
                }
                let dstr = String::from_utf8_lossy(&buf[idx..idx + dlen]).to_string();
                idx += dlen;
                dstr
            }
            SOCKS5_ATYP_IPV6 => {
                if buf.len() < idx + 16 + 2 {
                    return Err(MixedProxyError::BufferTooShort);
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[idx..idx + 16]);
                let ip = Ipv6Addr::from(octets);
                idx += 16;
                ip.to_string()
            }
            other => return Err(MixedProxyError::InvalidAddressType(other)),
        };

        if buf.len() < idx + 2 {
            return Err(MixedProxyError::BufferTooShort);
        }
        let target_port = u16::from_be_bytes([buf[idx], buf[idx + 1]]);
        idx += 2;

        Ok((
            Socks5Request {
                command,
                target_host,
                target_port,
                address_type: atyp,
            },
            idx,
        ))
    }

    /// Builds SOCKS5 command response.
    /// Format: [0x05, REP, 0x00, ATYP_IPV4, BND_IP(4B), BND_PORT(2B)]
    pub fn build_socks5_reply(rep: u8, bnd_port: u16, bnd_ip: [u8; 4]) -> [u8; 10] {
        let port_bytes = bnd_port.to_be_bytes();
        [
            SOCKS5_VERSION,
            rep,
            0x00,
            SOCKS5_ATYP_IPV4,
            bnd_ip[0],
            bnd_ip[1],
            bnd_ip[2],
            bnd_ip[3],
            port_bytes[0],
            port_bytes[1],
        ]
    }

    /// Parses HTTP proxy or HTTPS CONNECT header line.
    /// Example: `CONNECT host:443 HTTP/1.1` or `GET http://example.com/path HTTP/1.1`
    pub fn parse_http_proxy_request(header: &str) -> Result<HttpProxyRequest, MixedProxyError> {
        let first_line = header.lines().next().ok_or(MixedProxyError::MalformedHttpHeader)?;
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(MixedProxyError::MalformedHttpHeader);
        }

        let method = parts[0].to_uppercase();
        let raw_uri = parts[1];

        if method == "CONNECT" {
            let (host, port) = Self::parse_host_port(raw_uri, 443)?;
            Ok(HttpProxyRequest {
                method,
                host,
                port,
                path: String::new(),
                is_connect: true,
            })
        } else {
            // Standard HTTP proxy: URI is either absolute "http://host:port/path" or relative
            let trimmed = raw_uri.trim_start_matches("http://").trim_start_matches("https://");
            let slash_pos = trimmed.find('/').unwrap_or(trimmed.len());
            let host_part = &trimmed[..slash_pos];
            let path_part = &trimmed[slash_pos..];

            let (host, port) = Self::parse_host_port(host_part, 80)?;
            Ok(HttpProxyRequest {
                method,
                host,
                port,
                path: if path_part.is_empty() { "/".to_string() } else { path_part.to_string() },
                is_connect: false,
            })
        }
    }

    /// Generates standard HTTP 200 Connection Established response for CONNECT tunnels.
    pub fn build_http_connect_ok_response() -> &'static [u8] {
        b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: LumiNet-Mixed-Proxy/1.0\r\n\r\n"
    }

    fn parse_host_port(s: &str, default_port: u16) -> Result<(String, u16), MixedProxyError> {
        if let Some(colon_pos) = s.rfind(':') {
            let host = s[..colon_pos].trim_matches('[').trim_matches(']').to_string();
            let port_str = &s[colon_pos + 1..];
            let port = port_str.parse::<u16>().map_err(|_| MixedProxyError::MalformedHttpHeader)?;
            Ok((host, port))
        } else {
            Ok((s.to_string(), default_port))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_detection() {
        assert_eq!(detect_proxy_protocol(0x05), ProxyProtocolKind::Socks5);
        assert_eq!(detect_proxy_protocol(0x04), ProxyProtocolKind::Socks4);
        assert_eq!(detect_proxy_protocol(b'C'), ProxyProtocolKind::Http);
        assert_eq!(detect_proxy_protocol(b'G'), ProxyProtocolKind::Http);
        assert_eq!(detect_proxy_protocol(b'P'), ProxyProtocolKind::Http);
    }

    #[test]
    fn test_socks4_parse_and_reply() {
        // SOCKS4 standard IP
        let req_bytes = [
            0x04, 0x01, 0x01, 0xbb, // CMD=1 (CONNECT), PORT=443
            192, 168, 1, 100,       // IP=192.168.1.100
            b'a', b'd', b'm', b'i', b'n', 0x00, // USERID="admin"
        ];
        let (req, len) = MixedProtocolCodec::parse_socks4_request(&req_bytes).unwrap();
        assert_eq!(len, req_bytes.len());
        assert_eq!(req.command, SOCKS4_CMD_CONNECT);
        assert_eq!(req.port, 443);
        assert_eq!(req.ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(req.user_id, "admin");
        assert_eq!(req.domain, None);
        assert!(!req.is_socks4a());
        assert_eq!(req.target_host(), "192.168.1.100");

        // SOCKS4 reply
        let reply = MixedProtocolCodec::build_socks4_reply(Socks4ReplyStatus::Granted, 443, [0, 0, 0, 0]);
        assert_eq!(reply, [0x00, 0x5a, 0x01, 0xbb, 0, 0, 0, 0]);
    }

    #[test]
    fn test_socks4a_domain_parse() {
        // SOCKS4a IP 0.0.0.1 -> domain extension
        let mut req_bytes = vec![
            0x04, 0x01, 0x00, 0x50, // CMD=1, PORT=80
            0, 0, 0, 1,             // IP 0.0.0.1
            0x00,                   // empty user_id
        ];
        req_bytes.extend_from_slice(b"example.org\x00");

        let (req, len) = MixedProtocolCodec::parse_socks4_request(&req_bytes).unwrap();
        assert_eq!(len, req_bytes.len());
        assert!(req.is_socks4a());
        assert_eq!(req.domain.as_deref(), Some("example.org"));
        assert_eq!(req.target_host(), "example.org");
        assert_eq!(req.port, 80);
    }

    #[test]
    fn test_socks5_greeting_and_request() {
        // Greeting
        let greeting_bytes = [0x05, 0x02, 0x00, 0x02];
        let (greeting, len) = MixedProtocolCodec::parse_socks5_greeting(&greeting_bytes).unwrap();
        assert_eq!(len, 4);
        assert_eq!(greeting.methods, vec![0x00, 0x02]);

        let reply = MixedProtocolCodec::build_socks5_greeting_reply(SOCKS5_AUTH_NONE);
        assert_eq!(reply, [0x05, 0x00]);

        // Request Domain
        let mut req_bytes = vec![
            0x05, 0x01, 0x00, 0x03, // VER=5, CMD=1, RSV=0, ATYP=3 (domain)
            11,                      // domain len
        ];
        req_bytes.extend_from_slice(b"example.com");
        req_bytes.extend_from_slice(&8443u16.to_be_bytes());

        let (req, req_len) = MixedProtocolCodec::parse_socks5_request(&req_bytes).unwrap();
        assert_eq!(req_len, req_bytes.len());
        assert_eq!(req.command, SOCKS5_CMD_CONNECT);
        assert_eq!(req.target_host, "example.com");
        assert_eq!(req.target_port, 8443);

        // Command reply
        let cmd_reply = MixedProtocolCodec::build_socks5_reply(SOCKS5_REP_SUCCESS, 8443, [127, 0, 0, 1]);
        assert_eq!(cmd_reply[0], 0x05);
        assert_eq!(cmd_reply[1], 0x00);
        assert_eq!(cmd_reply[3], SOCKS5_ATYP_IPV4);
    }

    #[test]
    fn test_http_proxy_request() {
        // CONNECT
        let connect_hdr = "CONNECT cloudflare.com:443 HTTP/1.1\r\nHost: cloudflare.com:443\r\n\r\n";
        let parsed = MixedProtocolCodec::parse_http_proxy_request(connect_hdr).unwrap();
        assert!(parsed.is_connect);
        assert_eq!(parsed.host, "cloudflare.com");
        assert_eq!(parsed.port, 443);

        let ok_resp = MixedProtocolCodec::build_http_connect_ok_response();
        assert!(ok_resp.starts_with(b"HTTP/1.1 200 Connection Established"));

        // GET
        let get_hdr = "GET http://api.github.com/v1/status HTTP/1.1\r\nHost: api.github.com\r\n\r\n";
        let parsed_get = MixedProtocolCodec::parse_http_proxy_request(get_hdr).unwrap();
        assert!(!parsed_get.is_connect);
        assert_eq!(parsed_get.host, "api.github.com");
        assert_eq!(parsed_get.port, 80);
        assert_eq!(parsed_get.path, "/v1/status");
    }
}
