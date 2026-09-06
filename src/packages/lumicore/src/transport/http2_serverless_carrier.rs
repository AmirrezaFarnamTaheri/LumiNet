//! HTTP/2 Serverless Multiplexed Stream Carrier
//!
//! Envelopes raw proxy frames inside HTTP/2 DATA frames targeting serverless edge
//! workers and Google Apps Script forwarders.

#[derive(Debug, Clone)]
pub struct Http2ServerlessCarrier {
    pub endpoint_url: String,
    pub token: String,
}

impl Http2ServerlessCarrier {
    pub fn new(endpoint_url: &str, token: &str) -> Self {
        Self {
            endpoint_url: endpoint_url.to_string(),
            token: token.to_string(),
        }
    }

    /// Generates HTTP/2 frame envelope with Base64 payload encoding
    pub fn pack_frame(&self, stream_id: u32, data: &[u8]) -> Vec<u8> {
        let b64 = Self::base64_encode(data);
        format!(
            "{{\"stream_id\":{},\"token\":\"{}\",\"data\":\"{}\"}}",
            stream_id, self.token, b64
        )
        .into_bytes()
    }

    /// Unpacks frame envelope, returning stream_id and decoded raw bytes
    pub fn unpack_frame(&self, json_bytes: &[u8]) -> Option<(u32, Vec<u8>)> {
        let text = std::str::from_utf8(json_bytes).ok()?;
        let stream_id = Self::extract_json_u32(text, "stream_id")?;
        let b64 = Self::extract_json_str(text, "data")?;
        let data = Self::base64_decode(&b64)?;
        Some((stream_id, data))
    }

    fn extract_json_u32(json: &str, key: &str) -> Option<u32> {
        let pattern = format!("\"{}\":", key);
        let start = json.find(&pattern)? + pattern.len();
        let rest = &json[start..];
        let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        rest[..end].trim().parse::<u32>().ok()
    }

    fn extract_json_str(json: &str, key: &str) -> Option<String> {
        let pattern = format!("\"{}\":\"", key);
        let start = json.find(&pattern)? + pattern.len();
        let rest = &json[start..];
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    }

    fn base64_encode(data: &[u8]) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0];
            let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };

            result.push(CHARS[(b0 >> 2) as usize] as char);
            result.push(CHARS[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);
            if chunk.len() > 1 {
                result.push(CHARS[(((b1 & 15) << 2) | (b2 >> 6)) as usize] as char);
            } else {
                result.push('=');
            }
            if chunk.len() > 2 {
                result.push(CHARS[(b2 & 63) as usize] as char);
            } else {
                result.push('=');
            }
        }
        result
    }

    fn base64_decode(input: &str) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = 0u32;
        let mut bits = 0;

        for c in input.chars() {
            if c == '=' {
                break;
            }
            let val = match c {
                'A'..='Z' => (c as u8 - b'A') as u32,
                'a'..='z' => (c as u8 - b'a' + 26) as u32,
                '0'..='9' => (c as u8 - b'0' + 52) as u32,
                '+' => 62,
                '/' => 63,
                _ => continue,
            };
            buf = (buf << 6) | val;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
                buf &= (1 << bits) - 1;
            }
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serverless_carrier_pack_unpack() {
        let carrier = Http2ServerlessCarrier::new("https://worker.dev/tunnel", "auth-token");
        let payload = b"hello serverless relay";
        let packed = carrier.pack_frame(42, payload);

        let (stream_id, unpacked) = carrier.unpack_frame(&packed).unwrap();
        assert_eq!(stream_id, 42);
        assert_eq!(unpacked, payload);
    }
}
