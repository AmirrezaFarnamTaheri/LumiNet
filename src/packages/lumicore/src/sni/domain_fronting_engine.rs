//! Domain Fronting SNI / Host Discrepancy Engine
//!
//! Replaces or disguises the outer TLS Server Name Indication (SNI) with an allowed
//! legitimate CDN domain while retaining the true target hostname in the encrypted HTTP/1.1 or HTTP/2 headers.

#[derive(Debug, Clone)]
pub struct DomainFrontingEngine {
    pub outer_sni: String,
    pub inner_host: String,
}

impl DomainFrontingEngine {
    pub fn new(outer_sni: &str, inner_host: &str) -> Self {
        Self {
            outer_sni: outer_sni.to_string(),
            inner_host: inner_host.to_string(),
        }
    }

    /// Rewrites outgoing HTTP request headers to point to the inner hidden host
    pub fn transform_http_request(&self, request: &[u8]) -> Vec<u8> {
        let req_str = match std::str::from_utf8(request) {
            Ok(s) => s,
            Err(_) => return request.to_vec(),
        };

        let mut lines = Vec::new();
        for line in req_str.split("\r\n") {
            if line.to_lowercase().starts_with("host:") {
                lines.push(format!("Host: {}", self.inner_host));
            } else {
                lines.push(line.to_string());
            }
        }
        lines.join("\r\n").into_bytes()
    }

    /// Evaluates whether an outbound request matches the fronting configuration
    pub fn matches_outer(&self, sni: &str) -> bool {
        sni.eq_ignore_ascii_case(&self.outer_sni)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_fronting_transform() {
        let engine = DomainFrontingEngine::new("allowed-cdn.com", "blocked-service.org");
        assert!(engine.matches_outer("allowed-cdn.com"));
        assert!(!engine.matches_outer("other.com"));

        let raw_req = b"GET /index HTTP/1.1\r\nHost: allowed-cdn.com\r\nUser-Agent: test\r\n\r\n";
        let transformed = engine.transform_http_request(raw_req);
        let trans_str = String::from_utf8(transformed).unwrap();
        assert!(trans_str.contains("Host: blocked-service.org"));
        assert!(!trans_str.contains("Host: allowed-cdn.com"));
    }
}
