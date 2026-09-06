//
// HTTP steganographic transport. Selects a cover object from a payload
// corpus, hides plaintext into it via the `StegSession` trait, and emits
// the result as a normal-looking HTTP response.

use std::io::{Read, Write};
use std::sync::Arc;

use crate::transport::steg_transport::{StegConfig, StegSession};

/// HTTP-specific steg session configuration.
pub struct HttpStegConfig {
    pub name: &'static str,
    pub is_clientside: bool,
    pub persist_mode: bool,
    pub accepts_gzip: bool,
    pub is_gzipped: bool,
    pub post_reflection: bool,
    pub payloads: Arc<dyn PayloadCorpus + Send + Sync>,
}

impl StegConfig for HttpStegConfig {
    fn name(&self) -> &'static str {
        self.name
    }

    fn create_session(&self, _is_client: bool) -> Box<dyn StegSession> {
        let mut session = HttpStegSession {
            cfg: Arc::clone(&self.payloads),
            name: self.name,
            pending_out: Vec::new(),
            pending_in: Vec::new(),
            exhausted: false,
        };
        if !self.is_clientside {
            session.load_payload();
        }
        Box::new(session)
    }
}

/// Per-connection HTTP disguise engine.
pub struct HttpStegSession {
    cfg: Arc<dyn PayloadCorpus + Send + Sync>,
    name: &'static str,
    pending_out: Vec<u8>,
    pending_in: Vec<u8>,
    exhausted: bool,
}

impl HttpStegSession {
    fn load_payload(&mut self) {
        if let Some(p) = self.cfg.next(self.name) {
            self.pending_out = p;
        } else {
            self.exhausted = true;
        }
    }
}

impl StegSession for HttpStegSession {
    fn transmit_room(&self, preferred: usize, _min: usize, _max: usize) -> usize {
        if self.exhausted {
            return 0;
        }
        self.pending_out.len().min(preferred)
    }

    fn encode(&mut self, plaintext: &[u8], sink: &mut dyn Write) -> std::io::Result<()> {
        if self.exhausted || self.pending_out.is_empty() {
            return Ok(());
        }
        let take = plaintext.len().min(self.pending_out.len());
        for (dst, src) in self
            .pending_out
            .iter_mut()
            .rev()
            .take(take)
            .zip(plaintext.iter().rev())
        {
            *dst ^= *src;
        }
        sink.write_all(&self.pending_out)?;
        self.pending_out.clear();
        self.exhausted = true;
        Ok(())
    }

    fn decode(&mut self, source: &mut dyn Read, dest: &mut Vec<u8>) -> std::io::Result<usize> {
        if !self.pending_in.is_empty() {
            dest.extend_from_slice(&self.pending_in);
            let n = self.pending_in.len();
            self.pending_in.clear();
            return Ok(n);
        }
        let mut buf = [0u8; 4096];
        let n = source.read(&mut buf)?;
        if n > 0 {
            self.pending_in.extend_from_slice(&buf[..n]);
            dest.extend_from_slice(&self.pending_in);
        }
        Ok(n)
    }

    fn on_successful_recv(&mut self) {
        self.pending_in.clear();
    }

    fn on_corrupted_recv(&mut self) -> u32 {
        self.pending_in.clear();
        1
    }
}

/// Payload corpus iterator. Returns a fresh cover object per call.
pub trait PayloadCorpus: Send + Sync {
    fn next(&self, scheme: &str) -> Option<Vec<u8>>;
}

/// Fixed corpus over a static byte slice list.
#[derive(Debug, Default)]
pub struct StaticCorpus {
    payloads: Vec<Vec<u8>>,
    idx: std::sync::atomic::AtomicUsize,
}

impl StaticCorpus {
    pub fn new(payloads: Vec<Vec<u8>>) -> Self {
        Self {
            payloads,
            idx: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl PayloadCorpus for StaticCorpus {
    fn next(&self, _scheme: &str) -> Option<Vec<u8>> {
        let idx = self.idx.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.payloads.is_empty() {
            return None;
        }
        self.payloads.get(idx % self.payloads.len()).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_writes_xored_cover() {
        let cover = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nABCD".to_vec();
        let corpus = Arc::new(StaticCorpus::new(vec![cover.clone()]));
        let cfg = HttpStegConfig {
            name: "http",
            is_clientside: false,
            persist_mode: true,
            accepts_gzip: false,
            is_gzipped: false,
            post_reflection: false,
            payloads: corpus,
        };
        let mut session = cfg.create_session(false);
        let mut buf = Vec::new();
        session.encode(b"XY", &mut buf).unwrap();
        assert_eq!(buf.len(), cover.len());
        assert_eq!(buf[cover.len() - 2], b'C' ^ b'X');
        assert_eq!(buf[cover.len() - 1], b'D' ^ b'Y');
    }

    #[test]
    fn transmit_room_returns_remaining_payload_len() {
        let corpus = Arc::new(StaticCorpus::new(vec![b"0123456789".to_vec()]));
        let cfg = HttpStegConfig {
            name: "http",
            is_clientside: false,
            persist_mode: true,
            accepts_gzip: false,
            is_gzipped: false,
            post_reflection: false,
            payloads: corpus,
        };
        let session = cfg.create_session(false);
        assert_eq!(session.transmit_room(5, 1, 10), 5);
        assert_eq!(session.transmit_room(100, 1, 10), 10);
    }

    #[test]
    fn exhausted_session_returns_zero_room() {
        let corpus = Arc::new(StaticCorpus::new(vec![]));
        let cfg = HttpStegConfig {
            name: "http",
            is_clientside: false,
            persist_mode: true,
            accepts_gzip: false,
            is_gzipped: false,
            post_reflection: false,
            payloads: corpus,
        };
        let session = cfg.create_session(false);
        assert_eq!(session.transmit_room(10, 1, 10), 0);
    }
}
