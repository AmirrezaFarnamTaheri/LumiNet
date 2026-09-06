//! # WebSocket Tunnel Protocol
//!
//! NAT traversal tunnel using WebSocket connections.
//!
//! Protocol: Client connects to server via WebSocket, server assigns
//! public port, forwards incoming connections through WebSocket frames.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Tunnel message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Login/authentication message.
    Login = 1,
    /// Swap/forward data message.
    Swap = 2,
    /// Forward request message.
    Forward = 3,
    /// Log message.
    Log = 4,
}

impl MessageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Login),
            2 => Some(Self::Swap),
            3 => Some(Self::Forward),
            4 => Some(Self::Log),
            _ => None,
        }
    }
}

/// WebSocket tunnel frame.
#[derive(Debug, Clone)]
pub struct TunnelFrame {
    pub msg_type: MessageType,
    pub payload: Vec<u8>,
}

impl TunnelFrame {
    /// Encodes the frame to bytes: [type:1][content][newline]
    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(1 + self.payload.len() + 1);
        data.push(self.msg_type as u8);
        data.extend_from_slice(&self.payload);
        data.push(b'\n');
        data
    }

    /// Decodes a frame from bytes.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        let msg_type = MessageType::from_u8(data[0])?;
        let payload = if data.last() == Some(&b'\n') {
            data[1..data.len() - 1].to_vec()
        } else {
            data[1..].to_vec()
        };
        Some(Self { msg_type, payload })
    }
}

/// UDP datagram with 2-byte big-endian length prefix.
pub fn encode_udp_datagram(data: &[u8]) -> Vec<u8> {
    let len = data.len() as u16;
    let mut encoded = Vec::with_capacity(2 + data.len());
    encoded.extend_from_slice(&len.to_be_bytes());
    encoded.extend_from_slice(data);
    encoded
}

/// Decodes a UDP datagram with 2-byte length prefix.
pub fn decode_udp_datagram(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + len {
        return None;
    }
    Some(data[2..2 + len].to_vec())
}

/// Tunnel session state.
#[derive(Debug, Clone)]
pub struct TunnelSession {
    pub id: String,
    pub domain: Option<String>,
    pub connected_at: std::time::Instant,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// Manages active tunnel sessions.
pub struct SessionManager {
    sessions: Arc<Mutex<HashMap<String, TunnelSession>>>,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Registers a new session.
    pub async fn register(&self, id: String, domain: Option<String>) {
        let mut sessions = self.sessions.lock().await;
        sessions.insert(
            id.clone(),
            TunnelSession {
                id,
                domain,
                connected_at: std::time::Instant::now(),
                bytes_sent: 0,
                bytes_received: 0,
            },
        );
    }

    /// Removes a session.
    pub async fn remove(&self, id: &str) {
        let mut sessions = self.sessions.lock().await;
        sessions.remove(id);
    }

    /// Returns the number of active sessions.
    pub async fn count(&self) -> usize {
        self.sessions.lock().await.len()
    }

    /// Returns all active sessions.
    pub async fn list(&self) -> Vec<TunnelSession> {
        self.sessions.lock().await.values().cloned().collect()
    }
}

/// Bidirectional stream bridging.
pub async fn bridge_streams(
    mut reader: impl tokio::io::AsyncRead + Unpin,
    mut writer: impl tokio::io::AsyncWrite + Unpin,
) -> Result<u64, std::io::Error> {
    let mut total = 0u64;
    let mut buf = vec![0u8; 8192];
    loop {
        let n = tokio::io::AsyncReadExt::read(&mut reader, &mut buf).await?;
        if n == 0 {
            break;
        }
        tokio::io::AsyncWriteExt::write_all(&mut writer, &buf[..n]).await?;
        total += n as u64;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_encode_decode() {
        let frame = TunnelFrame {
            msg_type: MessageType::Login,
            payload: b"hello".to_vec(),
        };
        let encoded = frame.encode();
        let decoded = TunnelFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.msg_type, MessageType::Login);
        assert_eq!(decoded.payload, b"hello");
    }

    #[test]
    fn test_udp_datagram() {
        let data = b"test data";
        let encoded = encode_udp_datagram(data);
        let decoded = decode_udp_datagram(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[tokio::test]
    async fn test_session_manager() {
        let mgr = SessionManager::new();
        mgr.register("test-1".to_string(), None).await;
        assert_eq!(mgr.count().await, 1);
        mgr.remove("test-1").await;
        assert_eq!(mgr.count().await, 0);
    }
}
