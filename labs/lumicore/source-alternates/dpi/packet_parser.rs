use regex::bytes::Regex;
use once_cell::sync::Lazy;

pub struct PacketParser {
    pub active: bool,
}

struct L7Pattern {
    name: String,
    regex: Regex,
}

static PATTERNS: Lazy<Vec<L7Pattern>> = Lazy::new(|| {
    let raw = include_str!("l7_patterns.txt");
    let mut patterns = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(pos) = line.find(':') {
            let name = line[..pos].trim().to_string();
            let pattern_str = line[pos + 1..].trim();
            if let Ok(regex) = Regex::new(pattern_str) {
                patterns.push(L7Pattern { name, regex });
            }
        }
    }
    patterns
});

impl PacketParser {
    pub fn new() -> Self {
        Self { active: true }
    }

    /// Detect protocol name from connection payload bytes
    pub fn detect_protocol(&self, payload: &[u8]) -> Option<String> {
        if !self.active || payload.is_empty() {
            return None;
        }

        for pattern in PATTERNS.iter() {
            if pattern.regex.is_match(payload) {
                return Some(pattern.name.clone());
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_protocol_http() {
        let parser = PacketParser::new();
        // A valid HTTP response payload
        let payload = b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n";
        assert_eq!(parser.detect_protocol(payload), Some("http".to_string()));
    }

    #[test]
    fn test_detect_protocol_ssh() {
        let parser = PacketParser::new();
        // A typical SSH-2.0 greeting
        let payload = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n";
        assert_eq!(parser.detect_protocol(payload), Some("ssh".to_string()));
    }

    #[test]
    fn test_detect_protocol_unknown() {
        let parser = PacketParser::new();
        let payload = b"some random bytes that match nothing";
        assert_eq!(parser.detect_protocol(payload), None);
    }
}
