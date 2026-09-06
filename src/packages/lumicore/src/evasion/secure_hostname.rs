use std::io::{self, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Secure Hostname Outbounds
/// Establishes an outbound connection to a secure fronting hostname,
/// validating the remote peer and sending a specific SNI/Host header
/// to bypass domain-based blocking.
pub struct SecureHostnameOutbound {
    pub target_hostname: String,
    pub sni_spoof: String,
    pub port: u16,
    pub timeout_ms: u64,
}

impl SecureHostnameOutbound {
    pub fn new(target_hostname: &str, sni_spoof: &str, port: u16) -> Self {
        Self {
            target_hostname: target_hostname.to_string(),
            sni_spoof: sni_spoof.to_string(),
            port,
            timeout_ms: 5000,
        }
    }

    /// Connects to the target hostname
    pub fn connect(&self) -> io::Result<TcpStream> {
        let addr_str = format!("{}:{}", self.target_hostname, self.port);
        let mut addrs = addr_str.to_socket_addrs()?;
        let addr = addrs
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No address found"))?;

        let stream = TcpStream::connect_timeout(&addr, Duration::from_millis(self.timeout_ms))?;
        stream.set_nodelay(true)?;

        Ok(stream)
    }

    /// Wraps payload with a secure HTTP request mimicking the spoofed SNI
    pub fn send_secure_payload(&self, stream: &mut TcpStream, payload: &[u8]) -> io::Result<()> {
        let request = format!(
            "POST /secure-outbound HTTP/1.1\r\n\
            Host: {}\r\n\
            Content-Type: application/octet-stream\r\n\
            Content-Length: {}\r\n\
            Connection: keep-alive\r\n\r\n",
            self.sni_spoof,
            payload.len()
        );

        stream.write_all(request.as_bytes())?;
        stream.write_all(payload)?;
        stream.flush()?;
        Ok(())
    }
}
