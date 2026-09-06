//
// HTTP pluggable transport wrapping protocol. Reads bytes from an inner
// SOCKS-like bytestream and wraps them inside valid HTTP/1.1 GET/POST
// exchanges (request body / Cookie header fragments) to evade DPI that
// drops non-HTTP flows. Decodes the counterpart side back to raw bytes.
//
// ponytail: implements the wire *shape* (HTTP framing + cookie/body
// chunking) the way stegotorus does, without the full HTTP-steg
// payload-coding curves. Adequate against protocol classifiers that look
// at request structure; insufficient against statistical steg-analysis.
// Add the rate/coding curves in `coding/` if a censor upgrades counters.

use std::collections::VecDeque;

/// Number of bytes carried per HTTP cookie fragment (stegotorus default ~2048,
/// shrunk here so requests stay within common MTU/MSS without TCP segs).
const COOKIE_CHUNK_BYTES: usize = 1024;

/// HTTP steg encoder/decoder pair.
pub struct HttpSteg {
    outbound: VecDeque<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StegError {
    /// HTTP frame was malformed (not a valid request line / no recognizable payload slot).
    #[allow(dead_code)]
    MalformedFrame(String),
    /// Chunk hex size was missing or unparsable.
    BadChunkSize,
}

/// A single HTTP request carrying a slice of the wrapped stream.
pub struct HttpFrame {
    pub method: String,
    pub path: String,
    pub host: String,
    pub cookie: Option<String>,
    pub body: Vec<u8>,
}

impl HttpSteg {
    pub fn new() -> Self {
        Self {
            outbound: VecDeque::new(),
        }
    }

    /// Enqueue raw bytes to be wrapped into HTTP frames on the next call
    /// to [`HttpSteg::next_frame`].
    pub fn push_bytes(&mut self, bytes: &[u8]) {
        self.outbound.extend(bytes);
    }

    /// Wrap the next queued chunk as a GET request with a `Cookie` fragment
    /// carrying the bytes (hex-encoded). Returns `None` when the queue is
    /// drained. The decoder side reads the cookie back out.
    pub fn next_frame(&mut self) -> Option<HttpFrame> {
        if self.outbound.is_empty() {
            return None;
        }
        let take = self.outbound.len().min(COOKIE_CHUNK_BYTES);
        let mut chunk = Vec::with_capacity(take);
        for _ in 0..take {
            chunk.push(self.outbound.pop_front()?);
        }
        let cookie = hex_encode(&chunk);
        let path = format!("/{}/{}", chunk.len(), chunk_index_hash(&chunk));
        Some(HttpFrame {
            method: "GET".into(),
            path,
            host: "cdn-edge.lumi.net".into(),
            cookie: Some(cookie),
            body: Vec::new(),
        })
    }

    /// Encode a POST frame carrying `body_bytes` directly in the message body.
    /// POST body uses `chunked` transfer encoding because stegotorus lets the
    /// encoder interleave flushes without precomputing Content-Length.
    pub fn post_frame(&mut self, body_bytes: &[u8]) -> HttpFrame {
        let chunked = chunked_encode(body_bytes);
        HttpFrame {
            method: "POST".into(),
            path: "/upload".into(),
            host: "cdn-edge.lumi.net".into(),
            cookie: None,
            body: chunked,
        }
    }

    /// Encode an [`HttpFrame`] produced by either `next_frame` or `post_frame`
    /// into wire bytes (HTTP/1.1 request text).
    pub fn encode(&self, frame: &HttpFrame) -> Vec<u8> {
        let mut out = String::new();
        out.push_str(&format!("{} {} HTTP/1.1\r\n", frame.method, frame.path));
        out.push_str(&format!("Host: {}\r\n", frame.host));
        out.push_str("User-Agent: Mozilla/5.0 (luminet-steg)\r\n");
        out.push_str("Accept: */*\r\n");
        if let Some(c) = &frame.cookie {
            out.push_str(&format!("Cookie: steg={}\r\n", c));
        }
        if !frame.body.is_empty() {
            out.push_str("Transfer-Encoding: chunked\r\n");
        }
        out.push_str("Connection: keep-alive\r\n\r\n");
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&frame.body);
        bytes
    }

    /// Best-effort decoder: pull a `Cookie: steg=<hex>` segment or a chunked
    /// POST body out of a raw HTTP/1.1 request blob and feed the recovered
    /// bytes back to the caller. Stops at first unrecognized pattern.
    pub fn decode(&self, raw: &[u8]) -> Result<Vec<u8>, StegError> {
        let text = String::from_utf8_lossy(raw).into_owned();
        // Fast path: cookie-encoded GET frame.
        if let Some(rest) = text.find("Cookie: steg=") {
            let after = &text[rest + "Cookie: steg=".len()..];
            let end = after.find("\r\n").unwrap_or(after.len());
            let hex = &after[..end];
            return hex_decode(hex).map_err(|_| StegError::BadChunkSize);
        }
        // POST chunked path: locate the body separator then parse chunk size lines.
        if let Some(idx) = text.find("\r\n\r\n") {
            let body = &raw[idx + 4..];
            return chunked_decode(body);
        }
        Err(StegError::MalformedFrame("no cookie and no body".into()))
    }

    /// True when nothing is queued for outbound wrapping.
    pub fn is_idle(&self) -> bool {
        self.outbound.is_empty()
    }
}

impl Default for HttpSteg {
    fn default() -> Self {
        Self::new()
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, StegError> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return Err(StegError::BadChunkSize);
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, StegError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(StegError::BadChunkSize),
    }
}

fn chunk_index_hash(chunk: &[u8]) -> String {
    let mut h: u32 = 0x811C9DC5;
    for b in chunk {
        h ^= *b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    format!("{:08x}", h)
}

fn chunked_encode(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 16);
    let header = format!("{:x}\r\n", body.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(b"\r\n0\r\n\r\n");
    out
}

fn chunked_decode(body: &[u8]) -> Result<Vec<u8>, StegError> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 2 <= body.len() {
        // Parse hex chunk-size line up to CRLF.
        let crlf = body[i..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or(StegError::BadChunkSize)?;
        let size_str =
            std::str::from_utf8(&body[i..i + crlf]).map_err(|_| StegError::BadChunkSize)?;
        let size =
            usize::from_str_radix(size_str.trim(), 16).map_err(|_| StegError::BadChunkSize)?;
        i += crlf + 2;
        if size == 0 {
            break;
        }
        if i + size > body.len() {
            return Err(StegError::BadChunkSize);
        }
        out.extend_from_slice(&body[i..i + size]);
        i += size;
        // Skip trailing CRLF after chunk data.
        if i + 2 <= body.len() && &body[i..i + 2] == b"\r\n" {
            i += 2;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_frame_roundtrips() {
        let mut steg = HttpSteg::new();
        steg.push_bytes(b"hello world");
        let frame = steg.next_frame().unwrap();
        assert_eq!(frame.method, "GET");
        let bytes = steg.encode(&frame);
        let recovered = steg.decode(&bytes).unwrap();
        assert_eq!(recovered, b"hello world");
    }

    #[test]
    fn post_frame_roundtrips_chunked() {
        let mut steg = HttpSteg::new();
        let body = b"payload bytes for the POST body";
        let frame = steg.post_frame(body);
        let bytes = steg.encode(&frame);
        let recovered = steg.decode(&bytes).unwrap();
        assert_eq!(recovered, body);
    }

    #[test]
    fn empty_queue_yields_none() {
        let mut steg = HttpSteg::new();
        assert!(steg.is_idle());
        assert!(steg.next_frame().is_none());
    }
}
