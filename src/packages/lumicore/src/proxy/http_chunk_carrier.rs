//! HTTP Chunked Stream Carrier
//!
//! Encapsulates binary TCP/UDP proxy payloads inside HTTP/1.1 chunked transfer
//! encoding framing (<hex-size>\r\n<data>\r\n) and decodes incoming carrier streams.

use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum HttpChunkError {
    IncompleteChunk,
    InvalidChunkHeader,
    StreamTruncated,
}

impl fmt::Display for HttpChunkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompleteChunk => write!(f, "Incomplete chunk in buffer"),
            Self::InvalidChunkHeader => write!(f, "Invalid hex chunk header"),
            Self::StreamTruncated => write!(f, "HTTP stream truncated unexpectedly"),
        }
    }
}

impl std::error::Error for HttpChunkError {}

#[derive(Debug, Clone)]
pub struct HttpChunkCarrier {
    pub session_id: String,
    pub path: String,
    pub host: String,
}

impl HttpChunkCarrier {
    pub fn new(host: &str, path: &str, session_id: &str) -> Self {
        Self {
            host: host.to_string(),
            path: path.to_string(),
            session_id: session_id.to_string(),
        }
    }

    /// Formats the initial HTTP POST uplink handshake header
    pub fn create_uplink_header(&self) -> Vec<u8> {
        format!(
            "POST {} HTTP/1.1\r\n            Host: {}\r\n            Transfer-Encoding: chunked\r\n            Content-Type: application/octet-stream\r\n            X-Session-ID: {}\r\n            Connection: keep-alive\r\n            \r\n",
            self.path, self.host, self.session_id
        )
        .into_bytes()
    }

    /// Wraps raw payload bytes in an HTTP/1.1 chunk: `<hex-length>\r\n<payload>\r\n`
    pub fn encode_chunk(payload: &[u8]) -> Vec<u8> {
        let hex_len = format!("{:x}", payload.len());
        let mut out = Vec::with_capacity(hex_len.len() + 4 + payload.len());
        out.extend_from_slice(hex_len.as_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(payload);
        out.extend_from_slice(b"\r\n");
        out
    }

    /// Encodes terminal chunk (0\r\n\r\n)
    pub fn encode_terminal() -> Vec<u8> {
        b"0\r\n\r\n".to_vec()
    }

    /// Decodes a single chunk from a byte slice.
    /// Returns (payload, bytes_consumed)
    pub fn decode_chunk(buf: &[u8]) -> Result<(Vec<u8>, usize), HttpChunkError> {
        // Find CRLF after hex len
        let crlf = b"\r\n";
        let mut line_end = None;
        for i in 0..buf.len().saturating_sub(1) {
            if &buf[i..i + 2] == crlf {
                line_end = Some(i);
                break;
            }
        }

        let header_end = line_end.ok_or(HttpChunkError::IncompleteChunk)?;
        let hex_str = std::str::from_utf8(&buf[..header_end])
            .map_err(|_| HttpChunkError::InvalidChunkHeader)?;
        
        let chunk_size = usize::from_str_radix(hex_str.trim(), 16)
            .map_err(|_| HttpChunkError::InvalidChunkHeader)?;

        let data_start = header_end + 2;
        let data_end = data_start + chunk_size;
        let total_chunk_len = data_end + 2;

        if buf.len() < total_chunk_len {
            return Err(HttpChunkError::IncompleteChunk);
        }

        if &buf[data_end..total_chunk_len] != crlf {
            return Err(HttpChunkError::InvalidChunkHeader);
        }

        Ok((buf[data_start..data_end].to_vec(), total_chunk_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_encode_decode() {
        let carrier = HttpChunkCarrier::new("example.com", "/relay", "sess-123");
        let header = carrier.create_uplink_header();
        assert!(header.starts_with(b"POST /relay HTTP/1.1"));

        let payload = b"hello luminet chunk";
        let encoded = HttpChunkCarrier::encode_chunk(payload);
        assert!(encoded.starts_with(b"13\r\n")); // 19 in hex is 0x13

        let (decoded, consumed) = HttpChunkCarrier::decode_chunk(&encoded).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_terminal_chunk() {
        let term = HttpChunkCarrier::encode_terminal();
        let (decoded, consumed) = HttpChunkCarrier::decode_chunk(&term).unwrap();
        assert!(decoded.is_empty());
        assert_eq!(consumed, 5);
    }
}
