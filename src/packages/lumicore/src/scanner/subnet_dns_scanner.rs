use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub struct DnsServerCandidate {
    pub server_ip: String,
    pub response_time_ms: f64,
    pub is_responsive: bool,
    pub is_poisoned: bool,
}

#[derive(Debug, Default)]
pub struct SubnetDnsScanner {
    servers: HashMap<String, DnsServerCandidate>,
    expected_ip_for_probe: String,
}

impl SubnetDnsScanner {
    pub fn new(expected_ip: &str) -> Self {
        Self {
            servers: HashMap::new(),
            expected_ip_for_probe: expected_ip.to_string(),
        }
    }

    pub fn record_probe_result(&mut self, server_ip: &str, rtt_ms: f64, resolved_ip: Option<&str>) {
        let (responsive, poisoned) = match resolved_ip {
            Some(ip) => (true, ip != self.expected_ip_for_probe),
            None => (false, false),
        };

        self.servers.insert(server_ip.to_string(), DnsServerCandidate {
            server_ip: server_ip.to_string(),
            response_time_ms: rtt_ms,
            is_responsive: responsive,
            is_poisoned: poisoned,
        });
    }

    pub fn select_unpoisoned_fastest(&self) -> Option<&DnsServerCandidate> {
        self.servers.values()
            .filter(|s| s.is_responsive && !s.is_poisoned)
            .min_by(|a, b| a.response_time_ms.partial_cmp(&b.response_time_ms).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subnet_dns_scanner_evaluation() {
        let mut scanner = SubnetDnsScanner::new("93.184.216.34"); // expected IP for example.com

        // DNS 1: normal
        scanner.record_probe_result("1.1.1.1", 15.0, Some("93.184.216.34"));
        // DNS 2: poisoned
        scanner.record_probe_result("10.0.0.1", 5.0, Some("10.10.34.34"));
        // DNS 3: unresponsive
        scanner.record_probe_result("8.8.8.8", 0.0, None);

        let best = scanner.select_unpoisoned_fastest().expect("should find clean DNS");
        assert_eq!(best.server_ip, "1.1.1.1");
        assert_eq!(best.response_time_ms, 15.0);
    }
}
