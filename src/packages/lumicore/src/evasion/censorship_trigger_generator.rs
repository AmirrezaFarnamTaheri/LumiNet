//! # Censorship Trigger Probe Generator
//!
//! Synthesizes structured test packets containing known DPI keyword triggers
//! to verify the active evasion effectiveness of transport fragmentation,
//! TCP window clamping, and TLS camouflage engines.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeCategory {
    HostHeader,
    PathKeyword,
    SniPattern,
    DnsQueryName,
}

#[derive(Debug, Clone)]
pub struct TriggerProbeSpec {
    pub category: ProbeCategory,
    pub payload_string: String,
    pub expected_block_mechanism: String,
}

pub struct CensorshipTriggerGenerator {
    triggers: Vec<TriggerProbeSpec>,
}

impl CensorshipTriggerGenerator {
    pub fn new() -> Self {
        let mut gen = Self { triggers: Vec::new() };
        gen.populate_default_triggers();
        gen
    }

    fn populate_default_triggers(&mut self) {
        self.triggers.push(TriggerProbeSpec {
            category: ProbeCategory::SniPattern,
            payload_string: "zh.wikipedia.org".to_string(),
            expected_block_mechanism: "SNI_RST".to_string(),
        });
        self.triggers.push(TriggerProbeSpec {
            category: ProbeCategory::HostHeader,
            payload_string: "Host: epochtimes.com\r\n".to_string(),
            expected_block_mechanism: "HTTP_RESET".to_string(),
        });
        self.triggers.push(TriggerProbeSpec {
            category: ProbeCategory::DnsQueryName,
            payload_string: "www.youtube.com".to_string(),
            expected_block_mechanism: "DNS_POISON".to_string(),
        });
        self.triggers.push(TriggerProbeSpec {
            category: ProbeCategory::PathKeyword,
            payload_string: "/search?q=falun".to_string(),
            expected_block_mechanism: "HTTP_KEYWORD_RST".to_string(),
        });
    }

    pub fn add_custom_trigger(&mut self, cat: ProbeCategory, payload: &str, mechanism: &str) {
        self.triggers.push(TriggerProbeSpec {
            category: cat,
            payload_string: payload.to_string(),
            expected_block_mechanism: mechanism.to_string(),
        });
    }

    pub fn generate_http_probe(&self, target_host: &str, path: &str) -> Vec<u8> {
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: LumiProbe/1.0\r\nConnection: close\r\n\r\n",
            path, target_host
        );
        req.into_bytes()
    }

    pub fn get_probes_by_category(&self, cat: ProbeCategory) -> Vec<&TriggerProbeSpec> {
        self.triggers.iter().filter(|t| t.category == cat).collect()
    }

    pub fn total_probes(&self) -> usize {
        self.triggers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_censorship_trigger_generator() {
        let gen = CensorshipTriggerGenerator::new();
        assert!(gen.total_probes() >= 4);

        let sni_probes = gen.get_probes_by_category(ProbeCategory::SniPattern);
        assert!(!sni_probes.is_empty());
        assert_eq!(sni_probes[0].payload_string, "zh.wikipedia.org");

        let http_probe = gen.generate_http_probe("zh.wikipedia.org", "/wiki/Test");
        let probe_str = String::from_utf8_lossy(&http_probe);
        assert!(probe_str.contains("Host: zh.wikipedia.org"));
        assert!(probe_str.contains("GET /wiki/Test HTTP/1.1"));
    }
}
