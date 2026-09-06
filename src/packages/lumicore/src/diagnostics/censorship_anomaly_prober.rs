//! # Censorship Anomaly Prober
//!
//! Actively detects censorship interference mechanisms: TCP RST injection,
//! DNS wrong-answer pollution, UDP blackholing, and SNI connection termination.
//! Ported and enhanced from fqrouter/qiang.

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyType {
    TcpRstInjection,
    DnsPollutionWrongAnswer,
    UdpBlackhole,
    HttpKeywordBlock,
    SniReset,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InterferenceSignature {
    pub anomaly_type: AnomalyType,
    pub confidence: f32,
    pub details: String,
}

#[derive(Debug, Default, Clone)]
pub struct CensorshipAnomalyProber;

impl CensorshipAnomalyProber {
    pub fn new() -> Self {
        Self
    }

    /// Evaluates TCP RST characteristics to identify stateful middlebox injection
    /// versus legitimate server teardown. GFW RST packets often exhibit mismatched
    /// TTLs and out-of-order sequence numbers.
    pub fn probe_tcp_rst(
        &self,
        syn_ack_received: bool,
        rst_received_immediately: bool,
        rst_ttl: u8,
        syn_ack_ttl: u8,
    ) -> Option<InterferenceSignature> {
        if !rst_received_immediately {
            return None;
        }

        // If TTL difference between SYN/ACK and RST is significant, it's forged by a middlebox
        let ttl_diff = (rst_ttl as i16 - syn_ack_ttl as i16).abs();
        let confidence = if ttl_diff >= 5 {
            0.95
        } else if !syn_ack_received {
            0.85
        } else {
            0.60
        };

        Some(InterferenceSignature {
            anomaly_type: AnomalyType::TcpRstInjection,
            confidence,
            details: format!("TCP RST detected with TTL delta: {} (RST TTL: {}, SYN/ACK TTL: {})", ttl_diff, rst_ttl, syn_ack_ttl),
        })
    }

    /// Probes DNS response for bogus IP mappings characteristic of DNS pollution.
    pub fn probe_dns_wrong_answer(
        &self,
        domain: &str,
        returned_ips: &[IpAddr],
        is_known_bogus_ip: bool,
    ) -> Option<InterferenceSignature> {
        if is_known_bogus_ip {
            return Some(InterferenceSignature {
                anomaly_type: AnomalyType::DnsPollutionWrongAnswer,
                confidence: 0.99,
                details: format!("Domain {} resolved to known forged IP addresses: {:?}", domain, returned_ips),
            });
        }

        // Reserved / loopback / private IP returned for public domain
        for ip in returned_ips {
            let is_bogus = match ip {
                IpAddr::V4(v4) => {
                    v4.is_loopback() || v4.is_private() || v4.is_unspecified() || v4.octets()[0] == 0
                }
                IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
            };
            if is_bogus {
                return Some(InterferenceSignature {
                    anomaly_type: AnomalyType::DnsPollutionWrongAnswer,
                    confidence: 0.90,
                    details: format!("Public domain {} resolved to reserved IP: {}", domain, ip),
                });
            }
        }

        None
    }

    /// Probes UDP traffic for selective packet dropping or blackholing.
    pub fn probe_udp_drop(&self, sent_packets: u32, received_packets: u32) -> Option<InterferenceSignature> {
        if sent_packets < 5 {
            return None;
        }
        let loss_rate = (sent_packets.saturating_sub(received_packets)) as f32 / sent_packets as f32;
        if loss_rate >= 0.95 {
            Some(InterferenceSignature {
                anomaly_type: AnomalyType::UdpBlackhole,
                confidence: 0.92,
                details: format!("Severe UDP blackhole detected: {}% loss (sent: {}, recvd: {})", (loss_rate * 100.0) as u32, sent_packets, received_packets),
            })
        } else {
            None
        }
    }

    /// Probes SNI connection reset during TLS ClientHello transmission.
    pub fn probe_sni_reset(&self, domain: &str, handshake_interrupted_at_client_hello: bool) -> Option<InterferenceSignature> {
        if handshake_interrupted_at_client_hello {
            Some(InterferenceSignature {
                anomaly_type: AnomalyType::SniReset,
                confidence: 0.95,
                details: format!("Connection immediately terminated upon sending SNI: {}", domain),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_rst_probe() {
        let prober = CensorshipAnomalyProber::new();
        // Significant TTL delta indicates middlebox injection
        let sig = prober.probe_tcp_rst(true, true, 48, 56).unwrap();
        assert_eq!(sig.anomaly_type, AnomalyType::TcpRstInjection);
        assert!(sig.confidence >= 0.9);
    }

    #[test]
    fn test_dns_wrong_answer_probe() {
        let prober = CensorshipAnomalyProber::new();
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let sig = prober.probe_dns_wrong_answer("facebook.com", &[loopback], false).unwrap();
        assert_eq!(sig.anomaly_type, AnomalyType::DnsPollutionWrongAnswer);
        assert_eq!(sig.confidence, 0.90);
    }

    #[test]
    fn test_udp_drop_probe() {
        let prober = CensorshipAnomalyProber::new();
        let sig = prober.probe_udp_drop(10, 0).unwrap();
        assert_eq!(sig.anomaly_type, AnomalyType::UdpBlackhole);
        assert!(sig.confidence > 0.9);
    }
}
