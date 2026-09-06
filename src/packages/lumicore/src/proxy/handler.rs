//! # Proxy Handler with Session Info
//!
//! SOCKS5/HTTP CONNECT proxy with session info embedding for per-app routing.
//!
//! Key feature: Session info embedding adds protocol, source IP, and port
//! to the SOCKS5 username (via "+info" marker) for Android per-app routing.

use std::net::SocketAddr;

/// Session info for proxy connections.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub protocol: String,
    pub domain: Option<String>,
}

/// SOCKS5 proxy state machine.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SocksState {
    ClientHello,
    ServerHello,
    SendAuthData,
    ReceiveAuthResponse,
    SendRequest,
    ReceiveResponse,
    Established,
}

/// SOCKS version.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SocksVersion {
    V4,
    V5,
}

/// SOCKS5 command.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SocksCommand {
    Connect,
    UdpAssociate,
}

/// SOCKS5 proxy handler with session info embedding.
pub struct SocksProxy {
    server_addr: SocketAddr,
    info: SessionInfo,
    state: SocksState,
    version: SocksVersion,
    command: SocksCommand,
    credentials: Option<SocksCredentials>,
    client_outbuf: Vec<u8>,
    server_outbuf: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SocksCredentials {
    pub username: String,
    pub password: String,
}

/// Session info marker for per-app routing.
/// When username ends with this marker, session info is appended.
const SESSION_INFO_MARKER: &str = "+info";

impl SocksProxy {
    /// Creates a new SOCKS5 proxy handler.
    pub fn new(
        server_addr: SocketAddr,
        info: SessionInfo,
        version: SocksVersion,
        command: SocksCommand,
        credentials: Option<SocksCredentials>,
    ) -> Self {
        let mut proxy = Self {
            server_addr,
            info,
            state: SocksState::ClientHello,
            version,
            command,
            credentials,
            client_outbuf: Vec::new(),
            server_outbuf: Vec::new(),
        };
        proxy.send_client_hello();
        proxy
    }

    /// Sends the initial SOCKS handshake.
    fn send_client_hello(&mut self) {
        match self.version {
            SocksVersion::V4 => self.send_client_hello_socks4(),
            SocksVersion::V5 => self.send_client_hello_socks5(),
        }
    }

    fn send_client_hello_socks4(&mut self) {
        self.server_outbuf.push(self.version as u8);
        self.server_outbuf.push(self.command as u8);
        self.server_outbuf
            .extend_from_slice(&self.info.dst.port().to_be_bytes());

        // SOCKS4a: if domain is provided, use 0.0.0.x + domain
        if let Some(ref domain) = self.info.domain {
            self.server_outbuf.extend_from_slice(&[0, 0, 0, 1]);
            self.server_outbuf.extend_from_slice(domain.as_bytes());
            self.server_outbuf.push(0);
        } else {
            if let SocketAddr::V4(v4) = self.info.dst {
                self.server_outbuf.extend_from_slice(&v4.ip().octets());
            }
        }

        self.state = SocksState::ServerHello;
    }

    fn send_client_hello_socks5(&mut self) {
        self.server_outbuf.extend_from_slice(&[0x05]); // Version
        self.server_outbuf.push(2); // Number of methods
        self.server_outbuf.push(0x00); // No auth
        self.server_outbuf.push(0x02); // Username/password

        self.state = SocksState::ServerHello;
    }

    /// Sends auth data with session info embedding.
    pub fn send_auth_data(&mut self) {
        let creds = match &self.credentials {
            Some(c) => c,
            None => return,
        };

        // Check for session info marker
        let username = if creds.username.ends_with(SESSION_INFO_MARKER) {
            let base = &creds.username[..creds.username.len() - SESSION_INFO_MARKER.len()];
            let proto = match self.command {
                SocksCommand::Connect => "tcp",
                SocksCommand::UdpAssociate => "udp",
            };
            format!(
                "{}|{}|{}|{}",
                base,
                proto,
                self.info.src.ip(),
                self.info.src.port()
            )
        } else {
            creds.username.clone()
        };

        // SOCKS5 username/password auth (RFC 1929)
        self.server_outbuf.push(0x01); // Version
        self.server_outbuf.push(username.len() as u8);
        self.server_outbuf.extend_from_slice(username.as_bytes());
        self.server_outbuf.push(creds.password.len() as u8);
        self.server_outbuf
            .extend_from_slice(creds.password.as_bytes());

        self.state = SocksState::ReceiveAuthResponse;
    }

    /// Sends the SOCKS5 CONNECT/UDP ASSOCIATE request.
    pub fn send_request(&mut self) {
        self.server_outbuf.push(0x05); // Version
        self.server_outbuf.push(self.command as u8); // Command
        self.server_outbuf.push(0x00); // Reserved

        // Address
        if let Some(ref domain) = self.info.domain {
            // Domain address
            self.server_outbuf.push(0x03); // ATYP: domain
            self.server_outbuf.push(domain.len() as u8);
            self.server_outbuf.extend_from_slice(domain.as_bytes());
        } else {
            match self.info.dst {
                SocketAddr::V4(v4) => {
                    self.server_outbuf.push(0x01); // ATYP: IPv4
                    self.server_outbuf.extend_from_slice(&v4.ip().octets());
                }
                SocketAddr::V6(v6) => {
                    self.server_outbuf.push(0x04); // ATYP: IPv6
                    self.server_outbuf.extend_from_slice(&v6.ip().octets());
                }
            }
        }

        // Port
        self.server_outbuf
            .extend_from_slice(&self.info.dst.port().to_be_bytes());

        self.state = SocksState::ReceiveResponse;
    }

    /// Returns the data to send to the proxy server.
    pub fn take_server_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.server_outbuf)
    }

    /// Feeds data received from the proxy server.
    pub fn feed_server_input(&mut self, data: &[u8]) {
        self.client_outbuf.extend_from_slice(data);
    }

    /// Returns the current state.
    pub fn state(&self) -> SocksState {
        self.state
    }

    /// Returns the configured upstream proxy address.
    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    /// Returns true if the connection is established.
    pub fn is_established(&self) -> bool {
        self.state == SocksState::Established
    }
}

/// HTTP CONNECT proxy state machine.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HttpState {
    ExpectResponseHeaders,
    Established,
}

/// HTTP CONNECT proxy handler with digest auth support.
pub struct HttpProxy {
    server_addr: SocketAddr,
    info: SessionInfo,
    state: HttpState,
    credentials: Option<SocksCredentials>,
    server_outbuf: Vec<u8>,
    digest_nonce: Option<String>,
}

impl HttpProxy {
    /// Creates a new HTTP CONNECT proxy handler.
    pub fn new(
        server_addr: SocketAddr,
        info: SessionInfo,
        credentials: Option<SocksCredentials>,
    ) -> Self {
        let mut proxy = Self {
            server_addr,
            info,
            state: HttpState::ExpectResponseHeaders,
            credentials,
            server_outbuf: Vec::new(),
            digest_nonce: None,
        };
        proxy.send_connect_request();
        proxy
    }

    /// Returns the configured upstream proxy address.
    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    /// Sends the HTTP CONNECT request.
    fn send_connect_request(&mut self) {
        let host = if let Some(ref domain) = self.info.domain {
            format!("{}:{}", domain, self.info.dst.port())
        } else {
            self.info.dst.to_string()
        };

        // CONNECT request
        self.server_outbuf.extend_from_slice(b"CONNECT ");
        self.server_outbuf.extend_from_slice(host.as_bytes());
        self.server_outbuf.extend_from_slice(b" HTTP/1.1\r\nHost: ");
        self.server_outbuf.extend_from_slice(host.as_bytes());
        self.server_outbuf.extend_from_slice(b"\r\n");

        // Auth header
        if let Some(ref creds) = self.credentials {
            if let Some(ref nonce) = self.digest_nonce {
                // Digest auth
                let auth = format_digest_auth(creds, &host, nonce);
                self.server_outbuf.extend_from_slice(
                    format!("Proxy-Authorization: Digest {}\r\n", auth).as_bytes(),
                );
            } else {
                // Basic auth
                let auth = format_basic_auth(creds);
                self.server_outbuf.extend_from_slice(
                    format!("Proxy-Authorization: Basic {}\r\n", auth).as_bytes(),
                );
            }
        }

        self.server_outbuf.extend_from_slice(b"\r\n");
    }

    /// Returns the data to send to the proxy server.
    pub fn take_server_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.server_outbuf)
    }

    /// Processes response headers from the proxy.
    /// Returns true if connection is established (200 OK).
    pub fn process_response(&mut self, data: &[u8]) -> bool {
        let response = String::from_utf8_lossy(data);

        // Check for 200 OK
        if response.contains("HTTP/1.1 200") || response.contains("HTTP/1.0 200") {
            self.state = HttpState::Established;
            return true;
        }

        // Check for 407 Proxy Auth Required (digest challenge)
        if response.contains("HTTP/1.1 407") {
            if let Some(nonce_start) = response.find("nonce=\"") {
                let nonce_data = &response[nonce_start + 7..];
                if let Some(nonce_end) = nonce_data.find('"') {
                    self.digest_nonce = Some(nonce_data[..nonce_end].to_string());
                }
            }
        }

        false
    }

    /// Returns true if the connection is established.
    pub fn is_established(&self) -> bool {
        self.state == HttpState::Established
    }
}

/// Formats Basic auth header value.
fn format_basic_auth(creds: &SocksCredentials) -> String {
    use base64::Engine;
    let raw = format!("{}:{}", creds.username, creds.password);
    base64::engine::general_purpose::STANDARD.encode(raw.as_bytes())
}

/// Formats Digest auth header value.
fn format_digest_auth(creds: &SocksCredentials, uri: &str, nonce: &str) -> String {
    // Simplified digest auth (RFC 2617)
    let ha1 = md5_hash(&format!("{}:proxy:{}", creds.username, creds.password));
    let ha2 = md5_hash(&format!("CONNECT:{}", uri));
    let response = md5_hash(&format!("{}:{}:{}", ha1, nonce, ha2));

    format!(
        "username=\"{}\", realm=\"proxy\", nonce=\"{}\", uri=\"{}\", response=\"{}\"",
        creds.username, nonce, uri, response
    )
}

/// Simple MD5 hash helper.
fn md5_hash(input: &str) -> String {
    let result = md5::compute(input.as_bytes());
    format!("{:x}", result)
}

/// Proxy type enumeration.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProxyType {
    Socks5,
    Socks4,
    Http,
    Direct,
}

/// Proxy configuration.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub proxy_type: ProxyType,
    pub server: SocketAddr,
    pub credentials: Option<SocksCredentials>,
    pub session_info: Option<SessionInfo>,
}

impl ProxyConfig {
    /// Creates a SOCKS5 proxy config.
    pub fn socks5(server: SocketAddr, username: Option<String>, password: Option<String>) -> Self {
        Self {
            proxy_type: ProxyType::Socks5,
            server,
            credentials: username.zip(password).map(|(u, p)| SocksCredentials {
                username: u,
                password: p,
            }),
            session_info: None,
        }
    }

    /// Creates an HTTP CONNECT proxy config.
    pub fn http(server: SocketAddr, username: Option<String>, password: Option<String>) -> Self {
        Self {
            proxy_type: ProxyType::Http,
            server,
            credentials: username.zip(password).map(|(u, p)| SocksCredentials {
                username: u,
                password: p,
            }),
            session_info: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks5_session_info() {
        let creds = SocksCredentials {
            username: "user+info".to_string(),
            password: "pass".to_string(),
        };

        let info = SessionInfo {
            src: "192.168.1.1:12345".parse().unwrap(),
            dst: "10.0.0.1:443".parse().unwrap(),
            protocol: "tcp".to_string(),
            domain: Some("example.com".to_string()),
        };

        let mut proxy = SocksProxy::new(
            "127.0.0.1:1080".parse().unwrap(),
            info,
            SocksVersion::V5,
            SocksCommand::Connect,
            Some(creds),
        );

        // Should embed session info in username
        proxy.send_auth_data();
        let output = proxy.take_server_output();
        let output_str = String::from_utf8_lossy(&output);
        assert!(output_str.contains("user|tcp|192.168.1.1|12345"));
    }

    #[test]
    fn test_basic_auth() {
        let creds = SocksCredentials {
            username: "admin".to_string(),
            password: "secret".to_string(),
        };
        let auth = format_basic_auth(&creds);
        assert!(!auth.is_empty());
    }

    #[test]
    fn test_proxy_config() {
        let config = ProxyConfig::socks5(
            "127.0.0.1:1080".parse().unwrap(),
            Some("user".to_string()),
            Some("pass".to_string()),
        );
        assert_eq!(config.proxy_type, ProxyType::Socks5);
        assert!(config.credentials.is_some());
    }
}
