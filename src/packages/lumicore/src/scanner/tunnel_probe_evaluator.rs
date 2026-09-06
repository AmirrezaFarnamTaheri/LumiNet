//! Tunnel Probe Evaluator and False-Positive Middlebox Spoofing Detector.
//!
//! Evaluates multi-protocol tunnel probe results (TCP, TLS, HTTP, WebSocket, QUIC, DNS)
//! to calculate connectivity metrics (RTT, jitter, packet loss, stability), identify
//! ISP middlebox TCP-ACK spoofing (false positives), assign reliability grades (A+ to F),
//! and parse egress trace diagnostics.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttemptMetric {
    pub success: bool,
    pub duration_ms: i64,
    pub error_category: Option<String>,
}

impl AttemptMetric {
    pub fn ok(duration_ms: i64) -> Self {
        Self {
            success: true,
            duration_ms,
            error_category: None,
        }
    }

    pub fn fail(duration_ms: i64, err: impl Into<String>) -> Self {
        Self {
            success: false,
            duration_ms,
            error_category: Some(err.into()),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TcpProbeResult {
    pub success: bool,
    pub attempts: Vec<AttemptMetric>,
    pub median_rtt_ms: i64,
    pub consistency: f64,
    pub error_category: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TlsProbeResult {
    pub success: bool,
    pub handshake_ms: i64,
    pub version: Option<String>,
    pub cipher_suite: Option<String>,
    pub alpn: Option<String>,
    pub verified: bool,
    pub error_category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HttpProbe {
    pub method: String,
    pub url: String,
    pub status_code: i32,
    pub duration_ms: i64,
    pub redirected: bool,
    pub error_category: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct HttpProbeResult {
    pub success: bool,
    pub probes: Vec<HttpProbe>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct WsProbeResult {
    pub success: bool,
    pub status_code: i32,
    pub duration_ms: i64,
    pub error_category: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct UdpProbeResult {
    pub reachable: bool,
    pub attempts: Vec<AttemptMetric>,
    pub error_category: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct QuicProbeResult {
    pub success: bool,
    pub handshake_ms: i64,
    pub alpn: Option<String>,
    pub error_category: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DnsProbeResult {
    pub udp_responsive: bool,
    pub tcp_responsive: bool,
    pub answers: Vec<String>,
    pub attempts: Vec<AttemptMetric>,
    pub error_category: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ProbeMetrics {
    pub rtt_ms: i64,
    pub jitter_ms: i64,
    pub packet_loss_estimate: f64,
    pub stability_percent: f64,
    pub timeout_frequency: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScoreResult {
    pub numeric: i32,
    pub grade: String,
    pub classification: String,
    pub confidence: f64,
    pub false_positive: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TunnelScanReport {
    pub endpoint: String,
    pub host: String,
    pub port: u16,
    pub tcp: TcpProbeResult,
    pub tls: TlsProbeResult,
    pub http: HttpProbeResult,
    pub websocket: WsProbeResult,
    pub udp: UdpProbeResult,
    pub quic: QuicProbeResult,
    pub dns: DnsProbeResult,
    pub metrics: ProbeMetrics,
    pub score: Option<ScoreResult>,
}

pub struct TunnelProbeEvaluator;

impl TunnelProbeEvaluator {
    /// Computes network connection metrics (RTT, jitter, loss, stability, timeouts)
    /// across collected TCP, UDP, and DNS probe attempts.
    pub fn compute_metrics(
        tcp: &TcpProbeResult,
        udp: &UdpProbeResult,
        dns: &DnsProbeResult,
    ) -> ProbeMetrics {
        let mut attempts: Vec<&AttemptMetric> = Vec::new();
        attempts.extend(tcp.attempts.iter());
        attempts.extend(udp.attempts.iter());
        attempts.extend(dns.attempts.iter());

        let mut successful_durations: Vec<i64> = Vec::new();
        let mut timeouts: usize = 0;

        for a in &attempts {
            if a.success {
                successful_durations.push(a.duration_ms);
            }
            if let Some(ref err) = a.error_category {
                if err.eq_ignore_ascii_case("timeout") {
                    timeouts += 1;
                }
            }
        }

        // Calculate jitter as sample standard deviation of successful latencies
        let jitter = if successful_durations.len() > 1 {
            let sum: f64 = successful_durations.iter().map(|&v| v as f64).sum();
            let mean = sum / (successful_durations.len() as f64);
            let variance: f64 = successful_durations
                .iter()
                .map(|&v| {
                    let d = (v as f64) - mean;
                    d * d
                })
                .sum::<f64>()
                / (successful_durations.len() as f64);
            variance.sqrt().round() as i64
        } else {
            0
        };

        // Determine RTT: prefer TCP median RTT, else median of successful probe latencies
        let rtt = if tcp.median_rtt_ms > 0 {
            tcp.median_rtt_ms
        } else {
            Self::median_latency(&successful_durations)
        };

        let total_attempts = attempts.len();
        let success_ratio = if total_attempts > 0 {
            let ok_count = attempts.iter().filter(|a| a.success).count();
            (ok_count as f64) / (total_attempts as f64)
        } else {
            0.0
        };

        let loss = 1.0 - success_ratio;
        let timeout_freq = if total_attempts > 0 {
            (timeouts as f64) / (total_attempts as f64)
        } else {
            0.0
        };

        let mut stability = 100.0 * (1.0 - loss);
        if jitter > 250 {
            stability -= 15.0;
        }
        if timeout_freq > 0.25 {
            stability -= 20.0;
        }
        if stability < 0.0 {
            stability = 0.0;
        }

        ProbeMetrics {
            rtt_ms: rtt,
            jitter_ms: jitter,
            packet_loss_estimate: Self::round_two_dec(loss * 100.0),
            stability_percent: Self::round_two_dec(stability),
            timeout_frequency: Self::round_two_dec(timeout_freq * 100.0),
        }
    }

    /// Evaluates protocol test outcomes to score endpoint quality, detect middlebox spoofing,
    /// calculate confidence, and assign classification grade.
    pub fn score_probe(
        tcp: &TcpProbeResult,
        tls: &TlsProbeResult,
        http: &HttpProbeResult,
        ws: &WsProbeResult,
        quic: &QuicProbeResult,
        dns: &DnsProbeResult,
        metrics: &ProbeMetrics,
    ) -> ScoreResult {
        let mut points = 0;
        let mut reasons = Vec::new();

        if tcp.success {
            points += 25;
            reasons.push("tcp_connectivity".to_string());
        }
        if tcp.consistency >= 0.67 {
            points += 15;
            reasons.push("retry_consistency".to_string());
        }
        if tls.success {
            points += 20;
            reasons.push("tls_handshake".to_string());
        }
        if http.success {
            points += 8;
            reasons.push("http_behavior".to_string());
        }
        if ws.success {
            points += 10;
            reasons.push("websocket_upgrade".to_string());
        }
        if quic.success {
            points += 8;
            reasons.push("quic_handshake".to_string());
        }
        if dns.udp_responsive || dns.tcp_responsive {
            points += 6;
            reasons.push("dns_responsive".to_string());
        }

        if metrics.rtt_ms > 0 && metrics.rtt_ms < 150 {
            points += 5;
        }
        if metrics.jitter_ms < 80 {
            points += 5;
        }
        if metrics.stability_percent >= 90.0 {
            points += 8;
        }

        if points > 100 {
            points = 100;
        }

        // False positive detection:
        // Case 1: TCP succeeds, but retry consistency is low (< 0.67) indicating erratic ACK injection.
        // Case 2: TCP succeeds, but TLS, HTTP, WebSocket, QUIC, and DNS ALL fail. This indicates
        // middlebox SYN-ACK spoofing where TCP connects but higher application layers are blocked/dropped.
        let mut false_positive = tcp.success && tcp.consistency < 0.67;
        if tcp.success
            && !tls.success
            && !http.success
            && !ws.success
            && !quic.success
            && !dns.udp_responsive
            && !dns.tcp_responsive
        {
            false_positive = true;
        }

        let classification = if false_positive {
            "False Positive".to_string()
        } else if points >= 82 && tcp.consistency >= 0.67 && (tls.success || ws.success || quic.success) {
            "Tunnel Ready".to_string()
        } else if points >= 58 {
            "Partially Usable".to_string()
        } else if points >= 38 {
            "Unstable".to_string()
        } else {
            "Blocked".to_string()
        };

        let grade = Self::calculate_grade(points);
        let conf = Self::calculate_confidence(tcp, tls, http, ws, quic, metrics, false_positive);

        ScoreResult {
            numeric: points,
            grade,
            classification,
            confidence: Self::round_two_dec(conf),
            false_positive,
            reasons,
        }
    }

    /// Evaluates an entire scan report and updates its metrics and score.
    pub fn evaluate_report(report: &mut TunnelScanReport) {
        let metrics = Self::compute_metrics(&report.tcp, &report.udp, &report.dns);
        report.metrics = metrics.clone();
        let score = Self::score_probe(
            &report.tcp,
            &report.tls,
            &report.http,
            &report.websocket,
            &report.quic,
            &report.dns,
            &metrics,
        );
        report.score = Some(score);
    }

    /// Parses Cloudflare egress trace data (`https://www.cloudflare.com/cdn-cgi/trace`)
    /// extracting `ip` and uppercase `loc` (ISO alpha-2 country code).
    pub fn parse_cloudflare_trace(raw: &str) -> (Option<String>, Option<String>) {
        let mut ip = None;
        let mut loc = None;

        for line in raw.lines() {
            let line = line.trim();
            if let Some((k, v)) = line.split_once('=') {
                let key = k.trim();
                let val = v.trim();
                match key {
                    "ip" => {
                        if !val.is_empty() {
                            ip = Some(val.to_string());
                        }
                    }
                    "loc" => {
                        if !val.is_empty() {
                            loc = Some(val.to_ascii_uppercase());
                        }
                    }
                    _ => {}
                }
            }
        }
        (ip, loc)
    }

    fn calculate_grade(points: i32) -> String {
        match points {
            p if p >= 94 => "A+".to_string(),
            p if p >= 85 => "A".to_string(),
            p if p >= 72 => "B".to_string(),
            p if p >= 58 => "C".to_string(),
            p if p >= 38 => "D".to_string(),
            _ => "F".to_string(),
        }
    }

    fn calculate_confidence(
        tcp: &TcpProbeResult,
        tls: &TlsProbeResult,
        http: &HttpProbeResult,
        ws: &WsProbeResult,
        quic: &QuicProbeResult,
        metrics: &ProbeMetrics,
        false_positive: bool,
    ) -> f64 {
        let mut c = tcp.consistency * 45.0;
        if tls.success {
            c += 20.0;
        }
        if http.success || ws.success || quic.success {
            c += 20.0;
        }
        if metrics.stability_percent >= 85.0 {
            c += 15.0;
        }
        if false_positive {
            c -= 25.0;
        }
        if c < 0.0 {
            c = 0.0;
        }
        if c > 100.0 {
            c = 100.0;
        }
        c
    }

    fn median_latency(values: &[i64]) -> i64 {
        if values.is_empty() {
            return 0;
        }
        let mut sorted = values.to_vec();
        sorted.sort_unstable();
        sorted[sorted.len() / 2]
    }

    fn round_two_dec(val: f64) -> f64 {
        (val * 100.0).round() / 100.0
    }
}
