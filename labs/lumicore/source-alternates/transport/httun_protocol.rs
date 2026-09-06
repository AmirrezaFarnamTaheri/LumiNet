//! # HTTPun (HTTP Tunnel) Protocol
//!
//! Implements the HTTPun wire protocol — a minimal HTTP/1.1 CONNECT-based tunnel
//! with optional chunked-transfer obfuscation to evade HTTP proxy inspection.
//! Ported from httun-master.
//!
//! Modes:
//!   1. `CONNECT` — plain HTTP CONNECT tunnel.
//!   2. `chunked` — wraps tunnel data as chunked HTTP/1.1 body to mimic
//!      streaming transfers (e.g., video HLS), defeating length-based DPI.
//!
//! Client opens a TCP connection → sends HTTP CONNECT or POST → server responds
//! 200 OK → bidirectional raw tunnel follows.

use std::fmt::Write as FmtWrite;

/// Maximum chunk size for chunked transfer encoding.
pub const MAX_CHUNK_SIZE: usize = 8192;
/// Default HTTP/1.1 CONNECT port.
pub const DEFAULT_PROXY_PORT: u16 = 8080;

/// Builds a raw HTTP CONNECT request for the given target host:port.
///
/// ```text
/// CONNECT host:port HTTP/1.1\r\n
/// Host: host:port\r\n
/// Proxy-Connection: keep-alive\r\n
/// User-Agent: <agent>\r\n
/// \r\n
/// ```
pub fn build_connect_request(host: &str, port: u16, user_agent: &str) -> String {
    format!(
        "CONNECT {host}:{port} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         Proxy-Connection: keep-alive\r\n\
         User-Agent: {user_agent}\r\n\
         \r\n"
    )
}

/// Parses an HTTP response status line to extract the status code.
///
/// Returns `None` if the response is malformed.
pub fn parse_status_code(response: &[u8]) -> Option<u16> {
    let s = std::str::from_utf8(response).ok()?;
    let line = s.lines().next()?;
    // "HTTP/1.1 200 Connection established"
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }
    parts[1].parse().ok()
}

/// Builds an HTTP CONNECT success response (sent by the server).
pub fn build_connect_response(status: u16, reason: &str) -> String {
    format!("HTTP/1.1 {status} {reason}\r\nConnection: keep-alive\r\n\r\n")
}

/// Encodes `data` as a single HTTP chunked-transfer segment.
///
/// Format: `<hex_length>\r\n<data>\r\n`
pub fn encode_chunk(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 20);
    write!(out as &mut dyn std::io::Write, "{:X}\r\n", data.len()).ok();
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
    out
}

/// Decodes one chunk from a chunked-transfer stream.
///
/// Returns `(chunk_data, bytes_consumed)` or `ChunkError` on malformed input.
/// Returns `Ok((empty, consumed))` when the terminal chunk (`0\r\n\r\n`) is reached.
pub fn decode_chunk(buf: &[u8]) -> Result<(Vec<u8>, usize), ChunkError> {
    // Find the CRLF after the hex length
    let crlf = buf.windows(2).position(|w| w == b"\r\n")
        .ok_or(ChunkError::NoCrlf)?;

    let hex_str = std::str::from_utf8(&buf[..crlf])
        .map_err(|_| ChunkError::InvalidHex)?;
    let chunk_len = usize::from_str_radix(hex_str.trim(), 16)
        .map_err(|_| ChunkError::InvalidHex)?;

    if chunk_len == 0 {
        // Terminal chunk: `0\r\n\r\n`
        return Ok((vec![], crlf + 4)); // skip 0\r\n\r\n
    }

    let data_start = crlf + 2;
    let data_end = data_start + chunk_len;

    if buf.len() < data_end + 2 {
        return Err(ChunkError::Incomplete);
    }

    let chunk = buf[data_start..data_end].to_vec();
    Ok((chunk, data_end + 2)) // skip trailing \r\n
}

/// Splits `data` into chunks of at most `MAX_CHUNK_SIZE` bytes
/// and encodes each as a chunked-transfer segment, plus a terminal chunk.
pub fn encode_chunked_body(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in data.chunks(MAX_CHUNK_SIZE) {
        out.extend_from_slice(&encode_chunk(chunk));
    }
    // Terminal chunk
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

/// Decodes all chunks from a chunked-transfer body.
///
/// Returns the assembled payload or an error if the input is malformed.
pub fn decode_chunked_body(buf: &[u8]) -> Result<Vec<u8>, ChunkError> {
    let mut output = Vec::new();
    let mut offset = 0;
    loop {
        if offset >= buf.len() {
            break;
        }
        let (chunk, consumed) = decode_chunk(&buf[offset..])?;
        offset += consumed;
        if chunk.is_empty() {
            break; // terminal chunk
        }
        output.extend_from_slice(&chunk);
    }
    Ok(output)
}

/// Builds a POST-based HTTP tunnel request header (chunked mode).
///
/// Used when CONNECT is blocked — masquerades as a streaming upload.
pub fn build_post_tunnel_header(host: &str, path: &str, user_agent: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/octet-stream\r\n\
         Transfer-Encoding: chunked\r\n\
         Connection: keep-alive\r\n\
         User-Agent: {user_agent}\r\n\
         Cache-Control: no-cache\r\n\
         \r\n"
    )
}

/// Parses HTTP headers from a raw byte buffer.
///
/// Returns a map of header names (lowercased) to values.
pub fn parse_http_headers(buf: &[u8]) -> Option<std::collections::HashMap<String, String>> {
    let s = std::str::from_utf8(buf).ok()?;
    let header_end = s.find("\r\n\r\n")?;
    let header_section = &s[..header_end];
    let mut headers = std::collections::HashMap::new();
    for line in header_section.lines().skip(1) {
        if let Some(colon) = line.find(':') {
            let name = line[..colon].trim().to_lowercase();
            let value = line[colon + 1..].trim().to_string();
            headers.insert(name, value);
        }
    }
    Some(headers)
}

/// Errors from chunked decoding.
#[derive(Debug, thiserror::Error)]
pub enum ChunkError {
    #[error("no CRLF delimiter found in chunk header")]
    NoCrlf,
    #[error("invalid hex length in chunk header")]
    InvalidHex,
    #[error("buffer too short to contain the declared chunk length")]
    Incomplete,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_connect_request() {
        let req = build_connect_request("proxy.example.com", 443, "LumiNet/1.0");
        assert!(req.starts_with("CONNECT proxy.example.com:443 HTTP/1.1\r\n"));
        assert!(req.ends_with("\r\n\r\n"));
        assert!(req.contains("User-Agent: LumiNet/1.0"));
    }

    #[test]
    fn test_parse_status_200() {
        let resp = b"HTTP/1.1 200 Connection established\r\n\r\n";
        assert_eq!(parse_status_code(resp), Some(200));
    }

    #[test]
    fn test_parse_status_407() {
        let resp = b"HTTP/1.1 407 Proxy Auth Required\r\n\r\n";
        assert_eq!(parse_status_code(resp), Some(407));
    }

    #[test]
    fn test_chunk_encode_decode_roundtrip() {
        let data = b"Hello, chunked world!";
        let encoded = encode_chunk(data);
        let (decoded, _consumed) = decode_chunk(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_chunked_body_roundtrip() {
        let payload = b"This is a longer payload that may span multiple chunks if we set the limit low enough.";
        let encoded = encode_chunked_body(payload);
        let decoded = decode_chunked_body(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_terminal_chunk_decoded_as_empty() {
        let terminal = b"0\r\n\r\n";
        let (data, consumed) = decode_chunk(terminal).unwrap();
        assert!(data.is_empty());
        assert_eq!(consumed, 5);
    }

    #[test]
    fn test_parse_headers() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Custom: value\r\n\r\n";
        let headers = parse_http_headers(raw).unwrap();
        assert_eq!(headers.get("content-type").unwrap(), "text/html");
        assert_eq!(headers.get("x-custom").unwrap(), "value");
    }

    #[test]
    fn test_post_tunnel_header() {
        let hdr = build_post_tunnel_header("cdn.example.com", "/upload", "Mozilla/5.0");
        assert!(hdr.contains("Transfer-Encoding: chunked"));
        assert!(hdr.contains("Host: cdn.example.com"));
    }
}
