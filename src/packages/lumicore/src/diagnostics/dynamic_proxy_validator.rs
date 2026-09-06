// Pure Rust implementation: Dynamic Proxy Pool Validator

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocol {
    Http,
    Https,
    Socks4,
    Socks5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnonymityLevel {
    Transparent,
    Anonymous,
    Elite,
}

#[derive(Debug, Clone)]
pub struct ProxyValidationRecord {
    pub host: String,
    pub port: u16,
    pub protocol: ProxyProtocol,
    pub is_alive: bool,
    pub latency_ms: u64,
    pub anonymity: AnonymityLevel,
    pub last_checked_ms: u64,
}

pub struct DynamicProxyValidator {
    pub probe_timeout_ms: u64,
    pub pool: HashMap<String, ProxyValidationRecord>,
}

impl DynamicProxyValidator {
    pub fn new(probe_timeout_ms: u64) -> Self {
        Self {
            probe_timeout_ms,
            pool: HashMap::new(),
        }
    }

    pub fn craft_socks5_probe() -> Vec<u8> {
        // Handshake: version 5, 1 method, No Auth (0x00)
        vec![0x05, 0x01, 0x00]
    }

    pub fn craft_http_probe(target_host: &str) -> Vec<u8> {
        format!(
            "GET http://{}/generate_204 HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n",
            target_host, target_host
        )
        .into_bytes()
    }

    pub fn verify_socks5_handshake_response(resp: &[u8]) -> bool {
        // Expect 0x05 0x00 (version 5, NO AUTH)
        resp.len() >= 2 && resp[0] == 0x05 && resp[1] == 0x00
    }

    pub fn determine_anonymity(headers: &HashMap<String, String>, my_ip: &str) -> AnonymityLevel {
        let has_forwarded = headers.keys().any(|k| {
            let lower = k.to_ascii_lowercase();
            lower == "x-forwarded-for"
                || lower == "x-real-ip"
                || lower == "via"
                || lower == "forwarded"
                || lower == "client-ip"
        });

        if !has_forwarded {
            return AnonymityLevel::Elite;
        }

        // Check if our real IP is leaked in the headers
        let leaks_real_ip = headers.values().any(|v| v.contains(my_ip));
        if leaks_real_ip {
            AnonymityLevel::Transparent
        } else {
            AnonymityLevel::Anonymous
        }
    }

    pub fn record_probe_result(
        &mut self,
        host: &str,
        port: u16,
        protocol: ProxyProtocol,
        is_alive: bool,
        latency_ms: u64,
        anonymity: AnonymityLevel,
        now_ms: u64,
    ) {
        let key = format!("{}:{}", host, port);
        self.pool.insert(
            key,
            ProxyValidationRecord {
                host: host.to_string(),
                port,
                protocol,
                is_alive,
                latency_ms,
                anonymity,
                last_checked_ms: now_ms,
            },
        );
    }

    pub fn get_healthy_proxies(&self, max_latency_ms: u64) -> Vec<ProxyValidationRecord> {
        let mut healthy: Vec<ProxyValidationRecord> = self
            .pool
            .values()
            .filter(|p| p.is_alive && p.latency_ms <= max_latency_ms)
            .cloned()
            .collect();

        healthy.sort_by_key(|p| p.latency_ms);
        healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_craft_and_verify_socks5() {
        let probe = DynamicProxyValidator::craft_socks5_probe();
        assert_eq!(probe, vec![0x05, 0x01, 0x00]);

        assert!(DynamicProxyValidator::verify_socks5_handshake_response(&[0x05, 0x00]));
        assert!(!DynamicProxyValidator::verify_socks5_handshake_response(&[0x05, 0xff]));
        assert!(!DynamicProxyValidator::verify_socks5_handshake_response(&[0x04, 0x00]));
    }

    #[test]
    fn test_anonymity_evaluation() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "text/html".to_string());
        assert_eq!(DynamicProxyValidator::determine_anonymity(&headers, "203.0.113.195"), AnonymityLevel::Elite);

        headers.insert("Via".to_string(), "1.1 squid".to_string());
        assert_eq!(DynamicProxyValidator::determine_anonymity(&headers, "203.0.113.195"), AnonymityLevel::Anonymous);

        headers.insert("X-Forwarded-For".to_string(), "203.0.113.195".to_string());
        assert_eq!(DynamicProxyValidator::determine_anonymity(&headers, "203.0.113.195"), AnonymityLevel::Transparent);
    }

    #[test]
    fn test_pool_recording_and_filtering() {
        let mut validator = DynamicProxyValidator::new(5000);
        validator.record_probe_result("1.2.3.4", 8080, ProxyProtocol::Http, true, 120, AnonymityLevel::Elite, 1000);
        validator.record_probe_result("5.6.7.8", 1080, ProxyProtocol::Socks5, true, 450, AnonymityLevel::Anonymous, 1000);
        validator.record_probe_result("9.9.9.9", 8080, ProxyProtocol::Http, false, 5000, AnonymityLevel::Transparent, 1000);

        let fast = validator.get_healthy_proxies(300);
        assert_eq!(fast.len(), 1);
        assert_eq!(fast[0].host, "1.2.3.4");
    }
}
