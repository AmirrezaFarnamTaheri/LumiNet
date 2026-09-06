use quinn::{Connection, Endpoint};
use std::net::SocketAddr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TuicQuicError {
    #[error("Connect error: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("Connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("TLS Exporter error: {0}")]
    TlsExporter(String),
}

pub struct TuicQuic {
    pub endpoint: Option<Endpoint>,
}

impl Default for TuicQuic {
    fn default() -> Self {
        Self::new()
    }
}

impl TuicQuic {
    pub fn new() -> Self {
        TuicQuic { endpoint: None }
    }

    /// Establish a connection to the TUIC v5 QUIC server
    pub async fn connect(
        &mut self,
        server_addr: SocketAddr,
        server_name: &str,
        client_config: quinn::ClientConfig,
    ) -> Result<Connection, TuicQuicError> {
        let mut endpoint = Endpoint::client(SocketAddr::from(([0, 0, 0, 0], 0)))
            .map_err(|e| TuicQuicError::TlsExporter(e.to_string()))?;
        endpoint.set_default_client_config(client_config);

        let conn = endpoint.connect(server_addr, server_name)?.await?;

        self.endpoint = Some(endpoint);
        Ok(conn)
    }

    /// Export TLS Keying Material for token generation according to TUIC spec (RFC 5705)
    pub fn export_token(
        &self,
        connection: &Connection,
        uuid: &str,
        password: &str,
    ) -> Result<[u8; 32], TuicQuicError> {
        let mut token = [0u8; 32];
        connection
            .export_keying_material(&mut token, uuid.as_bytes(), password.as_bytes())
            .map_err(|e| TuicQuicError::TlsExporter(format!("{:?}", e)))?;
        Ok(token)
    }
}
