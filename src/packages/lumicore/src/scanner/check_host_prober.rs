use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use serde::{Deserialize, Serialize};

/// Canonical Iran check-host node identifiers used to detect censorship from inside the country.
pub const DEFAULT_IRAN_NODES: &[&str] = &[
    "ir1.node.check-host.net",
    "ir2.node.check-host.net",
    "ir3.node.check-host.net",
    "ir5.node.check-host.net",
    "ir6.node.check-host.net",
    "ir7.node.check-host.net",
    "ir8.node.check-host.net",
];

/// Probe method requested from edge vantage nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProbeMethod {
    Http,
    Ping,
    Dns,
}

impl fmt::Display for ProbeMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProbeMethod::Http => write!(f, "http"),
            ProbeMethod::Ping => write!(f, "ping"),
            ProbeMethod::Dns => write!(f, "dns"),
        }
    }
}

impl FromStr for ProbeMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "http" => Ok(ProbeMethod::Http),
            "ping" => Ok(ProbeMethod::Ping),
            "dns" => Ok(ProbeMethod::Dns),
            other => Err(format!("Unsupported probe method: {}", other)),
        }
    }
}

/// Censorship and reachability verdict based on vantage node quorum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CensorshipVerdict {
    Clean,
    Filtered,
    HighLoss,
    Degraded,
    Indeterminate,
}

impl fmt::Display for CensorshipVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CensorshipVerdict::Clean => write!(f, "clean"),
            CensorshipVerdict::Filtered => write!(f, "filtered"),
            CensorshipVerdict::HighLoss => write!(f, "high_loss"),
            CensorshipVerdict::Degraded => write!(f, "degraded"),
            CensorshipVerdict::Indeterminate => write!(f, "indeterminate"),
        }
    }
}

/// Detailed outcome for a single vantage node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeProbeDetail {
    pub node: String,
    pub responsive: bool,
    pub rtt_ms: Option<f64>,
    pub error: Option<String>,
    pub extra_info: Option<String>,
}

/// Complete multi-node assessment result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CheckHostAssessment {
    pub target: String,
    pub method: ProbeMethod,
    pub verdict: CensorshipVerdict,
    pub total_nodes: usize,
    pub responsive_nodes: usize,
    pub blocked_nodes: usize,
    pub avg_rtt_ms: Option<f64>,
    pub node_details: Vec<NodeProbeDetail>,
    pub is_ready: bool,
}

/// Multi-node check-host edge reachability and censorship prober.
#[derive(Debug, Clone)]
pub struct CheckHostProber {
    pub target: String,
    pub method: ProbeMethod,
    pub nodes: Vec<String>,
}

impl CheckHostProber {
    pub fn new(target: impl Into<String>, method: ProbeMethod) -> Self {
        CheckHostProber {
            target: target.into(),
            method,
            nodes: DEFAULT_IRAN_NODES.iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn with_custom_nodes(
        target: impl Into<String>,
        method: ProbeMethod,
        nodes: Vec<String>,
    ) -> Self {
        CheckHostProber {
            target: target.into(),
            method,
            nodes,
        }
    }

    /// Builds the URL to initiate the asynchronous probe across selected nodes.
    pub fn build_initiate_url(&self) -> String {
        let mut url = format!(
            "https://check-host.net/check-{}?host={}",
            self.method, self.target
        );
        for node in &self.nodes {
            url.push_str("&node=");
            url.push_str(node);
        }
        url
    }

    /// Builds the URL to poll for results given a request ID.
    pub fn build_result_url(request_id: &str) -> String {
        format!("https://check-host.net/check-result/{}", request_id)
    }

    /// Parses the JSON response from check-host initiation, returning the `request_id`.
    pub fn parse_initiate_response(json_str: &str) -> Result<String, String> {
        let val: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| format!("Invalid initiate JSON response: {}", e))?;

        if let Some(req_id) = val.get("request_id").and_then(|v| v.as_str()) {
            return Ok(req_id.to_string());
        }

        if let Some(msg) = val.get("error").and_then(|v| v.as_str()) {
            return Err(format!("Check-Host initiation error: {}", msg));
        }

        Err("No request_id found in Check-Host response".to_string())
    }

    /// Evaluates the censorship verdict based on responsive node count and loss metrics.
    pub fn evaluate_verdict(
        responsive: usize,
        total: usize,
        avg_loss_pct: f64,
    ) -> CensorshipVerdict {
        if total == 0 {
            return CensorshipVerdict::Indeterminate;
        }

        let responsive_ratio = (responsive as f64) / (total as f64);

        if responsive == 0 {
            CensorshipVerdict::Filtered
        } else if responsive_ratio >= 0.75 {
            if avg_loss_pct > 40.0 {
                CensorshipVerdict::HighLoss
            } else if avg_loss_pct > 15.0 {
                CensorshipVerdict::Degraded
            } else {
                CensorshipVerdict::Clean
            }
        } else if responsive_ratio <= 0.35 {
            CensorshipVerdict::Filtered
        } else {
            CensorshipVerdict::Degraded
        }
    }

    /// Parses the polling results payload and computes the quorum assessment.
    pub fn parse_result_response(
        &self,
        json_str: &str,
    ) -> Result<CheckHostAssessment, String> {
        let val: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| format!("Invalid result JSON payload: {}", e))?;

        let obj = val
            .as_object()
            .ok_or_else(|| "Result payload must be a JSON object of node results".to_string())?;

        let mut node_details = Vec::new();
        let mut responsive_count = 0usize;
        let mut blocked_count = 0usize;
        let mut rtt_sum = 0.0f64;
        let mut rtt_count = 0usize;
        let mut total_loss_sum = 0.0f64;
        let mut any_pending = false;

        for (node_name, node_val) in obj {
            if node_val.is_null() {
                any_pending = true;
                continue;
            }

            match self.method {
                ProbeMethod::Ping => {
                    let mut node_responsive = false;
                    let mut ping_rtts = Vec::new();
                    let mut node_err = None;

                    if let Some(outer_arr) = node_val.as_array() {
                        for item in outer_arr {
                            if let Some(inner_arr) = item.as_array() {
                                for sample in inner_arr {
                                    if let Some(sample_arr) = sample.as_array() {
                                        if let Some(status) = sample_arr.get(0).and_then(|s| s.as_str()) {
                                            if status == "OK" {
                                                if let Some(rtt_sec) = sample_arr.get(1).and_then(|r| r.as_f64()) {
                                                    ping_rtts.push(rtt_sec * 1000.0);
                                                }
                                            } else {
                                                node_err = Some(status.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    let node_loss = if ping_rtts.is_empty() {
                        100.0
                    } else {
                        node_responsive = true;
                        0.0
                    };
                    total_loss_sum += node_loss;

                    let avg_rtt = if !ping_rtts.is_empty() {
                        let mean = ping_rtts.iter().sum::<f64>() / (ping_rtts.len() as f64);
                        rtt_sum += mean;
                        rtt_count += 1;
                        Some(mean)
                    } else {
                        None
                    };

                    if node_responsive {
                        responsive_count += 1;
                    } else {
                        blocked_count += 1;
                    }

                    node_details.push(NodeProbeDetail {
                        node: node_name.clone(),
                        responsive: node_responsive,
                        rtt_ms: avg_rtt,
                        error: node_err,
                        extra_info: Some(format!("samples: {}", ping_rtts.len())),
                    });
                }
                ProbeMethod::Http => {
                    let mut node_responsive = false;
                    let mut node_rtt = None;
                    let mut node_err = None;
                    let mut extra = None;

                    if let Some(arr) = node_val.as_array() {
                        if let Some(first_attempt) = arr.get(0).and_then(|v| v.as_array()) {
                            let ok_flag = first_attempt.get(0).and_then(|v| v.as_i64()).unwrap_or(0);
                            let rtt_sec = first_attempt.get(1).and_then(|v| v.as_f64()).unwrap_or(0.0);
                            let phrase = first_attempt.get(2).and_then(|v| v.as_str()).unwrap_or("");
                            let status_code = first_attempt.get(3).map(|v| v.to_string()).unwrap_or_default();
                            let ip = first_attempt.get(4).and_then(|v| v.as_str()).unwrap_or("");

                            if ok_flag == 1 {
                                node_responsive = true;
                                let ms = rtt_sec * 1000.0;
                                node_rtt = Some(ms);
                                rtt_sum += ms;
                                rtt_count += 1;
                                extra = Some(format!("HTTP {} ({}) -> {}", status_code, phrase, ip));
                            } else {
                                node_err = Some(if !phrase.is_empty() {
                                    phrase.to_string()
                                } else {
                                    "HTTP request timed out or reset".to_string()
                                });
                                total_loss_sum += 100.0;
                            }
                        }
                    }

                    if node_responsive {
                        responsive_count += 1;
                    } else {
                        blocked_count += 1;
                    }

                    node_details.push(NodeProbeDetail {
                        node: node_name.clone(),
                        responsive: node_responsive,
                        rtt_ms: node_rtt,
                        error: node_err,
                        extra_info: extra,
                    });
                }
                ProbeMethod::Dns => {
                    let mut node_responsive = false;
                    let mut node_err = None;
                    let mut extra = None;

                    if let Some(arr) = node_val.as_array() {
                        if let Some(dns_map) = arr.get(0).and_then(|v| v.as_object()) {
                            if let Some(a_records) = dns_map.get("A").and_then(|v| v.as_array()) {
                                let ips: Vec<String> = a_records
                                    .iter()
                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                    .collect();
                                if !ips.is_empty() {
                                    node_responsive = true;
                                    extra = Some(format!("A: {}", ips.join(", ")));
                                }
                            }
                        }
                    }

                    if node_responsive {
                        responsive_count += 1;
                    } else {
                        node_err = Some("DNS resolution timed out or NXDOMAIN".to_string());
                        blocked_count += 1;
                        total_loss_sum += 100.0;
                    }

                    node_details.push(NodeProbeDetail {
                        node: node_name.clone(),
                        responsive: node_responsive,
                        rtt_ms: None,
                        error: node_err,
                        extra_info: extra,
                    });
                }
            }
        }

        let evaluated_nodes = responsive_count + blocked_count;
        let avg_loss = if evaluated_nodes > 0 {
            total_loss_sum / (evaluated_nodes as f64)
        } else {
            0.0
        };

        let avg_rtt = if rtt_count > 0 {
            Some(rtt_sum / (rtt_count as f64))
        } else {
            None
        };

        let verdict = Self::evaluate_verdict(responsive_count, evaluated_nodes, avg_loss);

        Ok(CheckHostAssessment {
            target: self.target.clone(),
            method: self.method,
            verdict,
            total_nodes: evaluated_nodes,
            responsive_nodes: responsive_count,
            blocked_nodes: blocked_count,
            avg_rtt_ms: avg_rtt,
            node_details,
            is_ready: !any_pending && evaluated_nodes > 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_construction_and_methods() {
        let prober = CheckHostProber::new("1.1.1.1", ProbeMethod::Ping);
        let url = prober.build_initiate_url();

        assert!(url.starts_with("https://check-host.net/check-ping?host=1.1.1.1"));
        for node in DEFAULT_IRAN_NODES {
            assert!(url.contains(&format!("&node={}", node)));
        }

        let http_prober = CheckHostProber::new("example.com", ProbeMethod::Http);
        assert!(http_prober.build_initiate_url().starts_with("https://check-host.net/check-http?host=example.com"));

        let dns_prober = CheckHostProber::new("example.com", ProbeMethod::Dns);
        assert!(dns_prober.build_initiate_url().starts_with("https://check-host.net/check-dns?host=example.com"));

        let result_url = CheckHostProber::build_result_url("req-12345");
        assert_eq!(result_url, "https://check-host.net/check-result/req-12345");
    }

    #[test]
    fn test_parse_initiate_response() {
        let ok_json = r#"{"ok": 1, "request_id": "7bf39a.c801b", "permanent_link": "https://check-host.net/check-result/7bf39a.c801b"}"#;
        let req_id = CheckHostProber::parse_initiate_response(ok_json).expect("should parse request_id");
        assert_eq!(req_id, "7bf39a.c801b");

        let err_json = r#"{"ok": 0, "error": "Invalid host"}"#;
        let err = CheckHostProber::parse_initiate_response(err_json);
        assert!(err.is_err());
    }

    #[test]
    fn test_parse_ping_results_and_verdict() {
        let prober = CheckHostProber::new("8.8.8.8", ProbeMethod::Ping);

        let ping_payload = r#"{
            "ir1.node.check-host.net": [[
                ["OK", 0.045],
                ["OK", 0.043],
                ["OK", 0.047],
                ["OK", 0.044]
            ]],
            "ir2.node.check-host.net": [[
                ["OK", 0.052],
                ["OK", 0.050]
            ]],
            "ir3.node.check-host.net": [[
                ["TIMEOUT", 0.0],
                ["TIMEOUT", 0.0]
            ]],
            "ir5.node.check-host.net": [[
                ["OK", 0.040],
                ["OK", 0.042]
            ]]
        }"#;

        let assessment = prober.parse_result_response(ping_payload).expect("should parse ping results");
        assert_eq!(assessment.total_nodes, 4);
        assert_eq!(assessment.responsive_nodes, 3);
        assert_eq!(assessment.blocked_nodes, 1);
        assert!(assessment.avg_rtt_ms.is_some());
        assert!(assessment.is_ready);
        assert!(matches!(assessment.verdict, CensorshipVerdict::Clean | CensorshipVerdict::Degraded));
    }

    #[test]
    fn test_parse_http_results_censorship_detection() {
        let prober = CheckHostProber::new("twitter.com", ProbeMethod::Http);

        let blocked_payload = r#"{
            "ir1.node.check-host.net": [[0, 5.0, "Connection timed out", null, null]],
            "ir2.node.check-host.net": [[0, 5.0, "Connection timed out", null, null]],
            "ir3.node.check-host.net": [[0, 3.0, "Connection reset by peer", null, null]],
            "ir5.node.check-host.net": [[0, 5.0, "Connection timed out", null, null]]
        }"#;

        let assessment = prober.parse_result_response(blocked_payload).expect("should parse http block");
        assert_eq!(assessment.responsive_nodes, 0);
        assert_eq!(assessment.blocked_nodes, 4);
        assert_eq!(assessment.verdict, CensorshipVerdict::Filtered);
    }

    #[test]
    fn test_parse_dns_results() {
        let prober = CheckHostProber::new("example.com", ProbeMethod::Dns);

        let dns_payload = r#"{
            "ir1.node.check-host.net": [{"A": ["93.184.216.34"], "TTL": 300}],
            "ir2.node.check-host.net": [{"A": ["10.10.34.34"], "TTL": 60}]
        }"#;

        let assessment = prober.parse_result_response(dns_payload).expect("should parse dns results");
        assert_eq!(assessment.responsive_nodes, 2);
        assert_eq!(assessment.blocked_nodes, 0);
        assert_eq!(assessment.verdict, CensorshipVerdict::Clean);
    }
}

