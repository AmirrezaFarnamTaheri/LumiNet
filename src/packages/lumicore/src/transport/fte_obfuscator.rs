use data_encoding::HEXLOWER;
use std::io::{Error, ErrorKind};

/// FteObfuscator encrypts/decrypts packet payloads matching a specific regular expression shape.
pub struct FteObfuscator {
    regex_pattern: String,
    slice_size: usize,
}

impl FteObfuscator {
    /// Creates a new FteObfuscator instance.
    pub fn new(pattern: &str, size: usize) -> Self {
        Self {
            regex_pattern: pattern.to_string(),
            slice_size: size,
        }
    }

    pub fn regex_pattern(&self) -> &str {
        &self.regex_pattern
    }

    pub fn slice_size(&self) -> usize {
        self.slice_size
    }

    /// Encodes arbitrary packet payloads into HTTP/SSH-like covertexts matching regex boundaries.
    pub fn encode(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut covertext = Vec::new();
        // Morph plaintext bytes based on target regex:
        // Default mockup handles: GET /<hex_representation> HTTP/1.1\r\n\r\n
        let hex_payload = HEXLOWER.encode(plaintext);
        let header = b"GET /";
        let footer = b" HTTP/1.1\r\n\r\n";

        covertext.extend_from_slice(header);
        covertext.extend_from_slice(hex_payload.as_bytes());
        covertext.extend_from_slice(footer);
        covertext
    }

    /// Decodes HTTP/SSH-like covertexts back into plaintext payloads.
    pub fn decode(&self, covertext: &[u8]) -> Result<Vec<u8>, Error> {
        if !covertext.starts_with(b"GET /") || !covertext.ends_with(b" HTTP/1.1\r\n\r\n") {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid covertext format",
            ));
        }
        let payload_hex = &covertext[5..covertext.len() - 13];
        let plaintext = HEXLOWER
            .decode(payload_hex)
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fte_obfuscator_roundtrip() {
        let fte = FteObfuscator::new("^GET /.* HTTP/1.1\\r\\n\\r\\n$", 256);
        let original = b"hello fte obfuscation";
        let encoded = fte.encode(original);
        assert!(encoded.starts_with(b"GET /"));
        assert!(encoded.ends_with(b" HTTP/1.1\r\n\r\n"));

        let decoded = fte.decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }
}
