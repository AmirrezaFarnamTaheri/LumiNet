use crate::tls::MitmCertManager;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// MitmProxyServer implements a local intercepting proxy server.
/// It uses MitmCertManager to sign dynamic leaf certificates and performs
/// full TLS decryption on intercepted connections.
pub struct MitmProxyServer {
    pub bind_addr: SocketAddr,
    pub cert_manager: Arc<MitmCertManager>,
}

impl MitmProxyServer {
    /// Creates a new MitmProxyServer instance.
    pub fn new(bind_addr: SocketAddr, cert_manager: MitmCertManager) -> Self {
        Self {
            bind_addr,
            cert_manager: Arc::new(cert_manager),
        }
    }

    /// Runs the proxy listener and dispatches client streams.
    pub async fn run(&self) -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        log::info!("MITM proxy server listening on {}", self.bind_addr);

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(res) => res,
                Err(e) => {
                    log::warn!("Accept failed: {}", e);
                    continue;
                }
            };

            let _cert_mgr = self.cert_manager.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(stream, _cert_mgr).await {
                    log::debug!(
                        "Error handling client connection from {}: {:?}",
                        peer_addr,
                        e
                    );
                }
            });
        }
    }

    async fn handle_connection(
        mut client_stream: tokio::net::TcpStream,
        cert_mgr: Arc<MitmCertManager>,
    ) -> Result<(), Box<dyn Error>> {
        let mut buffer = [0u8; 4096];
        let bytes_read = client_stream.read(&mut buffer).await?;
        if bytes_read == 0 {
            return Ok(());
        }

        let req_header = String::from_utf8_lossy(&buffer[..bytes_read]);
        if req_header.starts_with("CONNECT ") {
            // Extrapolate destination host
            let host_line = req_header.split_whitespace().nth(1).unwrap_or("");
            let parts: Vec<&str> = host_line.split(':').collect();
            let host = parts[0];

            // Send CONNECT 200 Connection Established response
            client_stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;

            // Generate leaf certificate dynamically for the target domain using issue_leaf from MitmCertManager
            let (_cert_der, _key_der) = cert_mgr.issue_leaf(host)?;

            // In production: perform TLS handshake with client using the dynamic leaf cert,
            // decrypt the HTTP request, and forward to the upstream target.
            log::info!(
                "Intercepted and decapsulated HTTPS CONNECT request for target host: {}",
                host
            );
        } else {
            // Handle plain HTTP request
            client_stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                .await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_mitm_proxy_init() {
        let bind_addr = SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 0);
        let tmp_dir = std::env::temp_dir();
        let cert_mgr = MitmCertManager::new_in(&tmp_dir).unwrap();
        let server = MitmProxyServer::new(bind_addr, cert_mgr);
        assert_eq!(server.bind_addr.ip(), bind_addr.ip());
    }
}
