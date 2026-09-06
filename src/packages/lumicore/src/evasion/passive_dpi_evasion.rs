#[derive(Debug, Clone)]
pub struct PassiveDpiEvasionConfig {
    pub fragment_size: usize,
    pub host_mangle: bool,
}

impl Default for PassiveDpiEvasionConfig {
    fn default() -> Self {
        Self {
            fragment_size: 40,
            host_mangle: true,
        }
    }
}

pub struct PassiveDpiEvasionEngine {
    config: PassiveDpiEvasionConfig,
}

impl PassiveDpiEvasionEngine {
    pub fn new(config: PassiveDpiEvasionConfig) -> Self {
        Self { config }
    }

    /// Fragment outbound payload into smaller TCP chunks to evade DPI signature matching.
    pub fn evade_payload(&self, payload: &[u8]) -> Vec<Vec<u8>> {
        if payload.is_empty() {
            return vec![Vec::new()];
        }

        let mut chunks = Vec::new();
        let mut pos = 0;

        while pos < payload.len() {
            let chunk_end = std::cmp::min(pos + self.config.fragment_size, payload.len());
            let mut chunk = payload[pos..chunk_end].to_vec();

            // Mangle Host header if present in the first chunk
            if self.config.host_mangle && pos == 0 {
                chunk = self.apply_host_mangle(chunk);
            }

            chunks.push(chunk);
            pos = chunk_end;
        }

        chunks
    }

    fn apply_host_mangle(&self, chunk: Vec<u8>) -> Vec<u8> {
        let chunk_str = String::from_utf8_lossy(&chunk);
        if chunk_str.contains("Host: ") {
            let mutated = chunk_str.replace("Host: ", "hOsT: ");
            return mutated.into_bytes();
        }
        chunk
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_fragmentation() {
        let config = PassiveDpiEvasionConfig {
            fragment_size: 10,
            host_mangle: false,
        };
        let engine = PassiveDpiEvasionEngine::new(config);

        let payload = b"abcdefghijklmnopqrstuvwxyz"; // 26 bytes
        let fragments = engine.evade_payload(payload);

        assert_eq!(fragments.len(), 3);
        assert_eq!(fragments[0], b"abcdefghij");
        assert_eq!(fragments[1], b"klmnopqrst");
        assert_eq!(fragments[2], b"uvwxyz");
    }

    #[test]
    fn test_host_header_mangling() {
        let config = PassiveDpiEvasionConfig {
            fragment_size: 100,
            host_mangle: true,
        };
        let engine = PassiveDpiEvasionEngine::new(config);

        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let fragments = engine.evade_payload(request);

        assert_eq!(fragments.len(), 1);
        let result_str = String::from_utf8(fragments[0].clone()).unwrap();
        assert!(result_str.contains("hOsT: example.com"));
    }
}
