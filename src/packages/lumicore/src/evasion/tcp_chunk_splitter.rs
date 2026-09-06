pub const TLS_HEADER_SIZE: usize = 5;
pub const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

pub fn is_tls_client_hello(data: &[u8]) -> bool {
    data.len() > TLS_HEADER_SIZE && data[0] == CONTENT_TYPE_HANDSHAKE && data[TLS_HEADER_SIZE] == HANDSHAKE_TYPE_CLIENT_HELLO
}

pub struct TcpChunkSplitter;

impl TcpChunkSplitter {
    pub fn split_bytes(data: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
        if chunk_size == 0 || data.is_empty() {
            return vec![data.to_vec()];
        }
        data.chunks(chunk_size).map(|c| c.to_vec()).collect()
    }

    pub fn mutate_http_header_case(header_line: &str) -> String {
        // e.g. "Host: example.com" -> "hOsT: example.com"
        let parts: Vec<&str> = header_line.splitn(2, ':').collect();
        if parts.len() == 2 {
            let mut mutated_key = String::new();
            for (idx, ch) in parts[0].chars().enumerate() {
                if idx % 2 == 0 {
                    mutated_key.push(ch.to_ascii_lowercase());
                } else {
                    mutated_key.push(ch.to_ascii_uppercase());
                }
            }
            format!("{}:{}", mutated_key, parts[1])
        } else {
            header_line.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_chunk_splitting_and_header_mutation() {
        let payload = b"GET /index.html HTTP/1.1";
        let chunks = TcpChunkSplitter::split_bytes(payload, 5);
        assert_eq!(chunks.len(), 5);
        assert_eq!(chunks[0], b"GET /");

        let mutated = TcpChunkSplitter::mutate_http_header_case("Host: example.com");
        assert_eq!(mutated, "hOsT: example.com");

        let mock_hello = [0x16, 0x03, 0x01, 0x00, 0x10, 0x01, 0x00];
        assert!(is_tls_client_hello(&mock_hello));
    }
}
