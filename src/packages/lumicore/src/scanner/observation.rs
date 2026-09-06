// SPDX-License-Identifier: MIT
// C5.2 — Observation: clean-room port of OONI measurexlite observation primitives.
// An Observation represents a structured diagnostic record from a single network
// probe. It carries TCP, TLS, DNS, and HTTP layer observations with timestamps,
// network path, and failure metadata.
// Reference: OONI measurexlite (measurexlite/observation.py)
// MIT License — no OONI source code copied.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// ObservationType classifies the network layer captured in an observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationType {
    Tcp,
    Tls,
    Dns,
    Http,
    Unknown,
}

/// TCP observation records a TCP connect attempt and its outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpObservation {
    /// Local address that initiated the connection.
    pub local_addr: Option<String>,
    /// Remote address that was contacted.
    pub remote_addr: Option<String>,
    /// Remote hostname that was resolved (may differ from remote_addr).
    pub hostname: Option<String>,
    /// TCP port on the remote host.
    pub port: u16,
    /// Whether the connection succeeded.
    pub success: bool,
    /// Connection establishment latency in milliseconds.
    pub latency_ms: Option<u64>,
    /// Failure reason string if the connection failed.
    pub failure: Option<String>,
    /// Whether the failure was a connection reset.
    pub reset: bool,
    /// Whether the failure was a timeout.
    pub timeout: bool,
    /// Whether a proxy was detected in the connection path.
    pub proxy: bool,
    /// Application-layer protocol detected (e.g. "http", "tls").
    pub alpn: Option<String>,
    /// TLS version negotiated (if TLS handshake was attempted).
    pub tls_version: Option<String>,
    /// TLS cipher suite negotiated.
    pub tls_cipher: Option<String>,
    /// Timestamp as Unix epoch milliseconds.
    pub t0_ms: u64,
    /// Timestamp as Unix epoch milliseconds at observation end.
    pub t1_ms: u64,
}

/// TLS observation records a TLS handshake attempt and its outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsObservation {
    /// Remote address.
    pub remote_addr: Option<String>,
    /// Server Name Indication sent.
    pub sni: Option<String>,
    /// Whether the handshake succeeded.
    pub success: bool,
    /// TLS version negotiated (e.g. "TLS1.3").
    pub version: Option<String>,
    /// Negotiated cipher suite name.
    pub cipher_suite: Option<String>,
    /// Server certificate fingerprint (SHA-256, hex).
    pub cert_fingerprint: Option<String>,
    /// Whether certificate verification passed.
    pub cert_valid: bool,
    /// Certificate notAfter timestamp (Unix epoch).
    pub cert_expiry: Option<u64>,
    /// Whether session resumption was used.
    pub resumed: bool,
    /// Whether the handshake was intercepted (extra certs in chain).
    pub intercepted: bool,
    /// Failure reason string.
    pub failure: Option<String>,
    /// JA3 fingerprint string (if computed).
    pub ja3: Option<String>,
    /// JA4 fingerprint string (if computed).
    pub ja4: Option<String>,
    /// Timestamp as Unix epoch milliseconds.
    pub t0_ms: u64,
    /// Timestamp as Unix epoch milliseconds at observation end.
    pub t1_ms: u64,
}

/// DNS observation records a DNS query and its responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsObservation {
    /// The hostname that was queried.
    pub query_name: String,
    /// Query type (A, AAAA, CNAME, etc.).
    pub query_type: String,
    /// DNS server that was queried.
    pub server: Option<String>,
    /// Whether the query succeeded.
    pub success: bool,
    /// Resolved IP addresses.
    pub answers: Vec<String>,
    /// CNAME chain if present.
    pub cnames: Vec<String>,
    /// Whether DNSSEC validation passed.
    pub dnssec_valid: bool,
    /// Whether a response was received.
    pub received: bool,
    /// Failure reason string.
    pub failure: Option<String>,
    /// Response latency in milliseconds.
    pub latency_ms: Option<u64>,
    /// Whether this was a DNS-over-HTTPS query.
    pub doh: bool,
    /// Whether this was a DNS-over-TLS query.
    pub dot: bool,
    /// Timestamp as Unix epoch milliseconds.
    pub t0_ms: u64,
    /// Timestamp as Unix epoch milliseconds at observation end.
    pub t1_ms: u64,
}

/// HTTP observation records an HTTP request and response pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpObservation {
    /// The request URL.
    pub url: String,
    /// HTTP method used.
    pub method: String,
    /// Response status code.
    pub status_code: Option<u16>,
    /// Response headers.
    pub headers: Vec<(String, String)>,
    /// Content-Type of the response body.
    pub content_type: Option<String>,
    /// Content-Length from headers.
    pub content_length: Option<i64>,
    /// Whether the body matched the Content-Length header.
    pub body_length_match: bool,
    /// Whether the server is behind a DPI (blocked keywords in body).
    pub dpi_detected: bool,
    /// Keywords found in body indicating blocking.
    pub blocked_keywords: Vec<String>,
    /// HTTP/2 or HTTP/3 negotiated.
    pub http_version: Option<String>,
    /// TLS version (if HTTPS).
    pub tls_version: Option<String>,
    /// Whether the request was redirected.
    pub redirected: bool,
    /// Final URL after all redirects.
    pub final_url: Option<String>,
    /// Failure reason string.
    pub failure: Option<String>,
    /// Timestamp as Unix epoch milliseconds.
    pub t0_ms: u64,
    /// Timestamp as Unix epoch milliseconds at observation end.
    pub t1_ms: u64,
}

/// Observation is the top-level enum wrapping all observation types.
/// This mirrors the OONI measurexlite Observation class hierarchy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Observation {
    Tcp(TcpObservation),
    Tls(TlsObservation),
    Dns(DnsObservation),
    Http(HttpObservation),
}

impl Observation {
    /// Returns the observation type discriminator.
    pub fn observation_type(&self) -> ObservationType {
        match self {
            Observation::Tcp(_) => ObservationType::Tcp,
            Observation::Tls(_) => ObservationType::Tls,
            Observation::Dns(_) => ObservationType::Dns,
            Observation::Http(_) => ObservationType::Http,
        }
    }

    /// Returns the start timestamp (t0) in Unix milliseconds.
    pub fn t0_ms(&self) -> u64 {
        match self {
            Observation::Tcp(o) => o.t0_ms,
            Observation::Tls(o) => o.t0_ms,
            Observation::Dns(o) => o.t0_ms,
            Observation::Http(o) => o.t0_ms,
        }
    }

    /// Returns the end timestamp (t1) in Unix milliseconds.
    pub fn t1_ms(&self) -> u64 {
        match self {
            Observation::Tcp(o) => o.t1_ms,
            Observation::Tls(o) => o.t1_ms,
            Observation::Dns(o) => o.t1_ms,
            Observation::Http(o) => o.t1_ms,
        }
    }

    /// Returns the remote address as a string, if present.
    pub fn remote_addr(&self) -> Option<String> {
        match self {
            Observation::Tcp(o) => o.remote_addr.clone(),
            Observation::Tls(o) => o.remote_addr.clone(),
            Observation::Dns(o) => o.server.clone(),
            Observation::Http(o) => Some(o.url.clone()),
        }
    }

    /// Returns the network path (source IP) if available.
    pub fn local_addr(&self) -> Option<String> {
        match self {
            Observation::Tcp(o) => o.local_addr.clone(),
            _ => None,
        }
    }

    /// Whether this observation represents a failure.
    pub fn is_failure(&self) -> bool {
        match self {
            Observation::Tcp(o) => !o.success,
            Observation::Tls(o) => !o.success,
            Observation::Dns(o) => !o.success,
            Observation::Http(o) => o.status_code.is_none(),
        }
    }
}

/// ObservationSet holds a collection of observations that may originate from
/// the same network probe session. It provides merge and filter operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObservationSet {
    /// The list of observations in the set.
    pub observations: Vec<Observation>,
    /// An optional session identifier.
    pub session_id: Option<String>,
    /// Probe start time (Unix epoch milliseconds).
    pub probe_start_ms: u64,
    /// Probe end time (Unix epoch milliseconds).
    pub probe_end_ms: u64,
}

impl ObservationSet {
    /// Creates a new empty ObservationSet.
    pub fn new() -> Self {
        let now = unix_time_ms();
        Self {
            observations: Vec::new(),
            session_id: None,
            probe_start_ms: now,
            probe_end_ms: now,
        }
    }

    /// Adds an observation to the set and updates probe timestamps.
    pub fn add(&mut self, obs: Observation) {
        let t0 = obs.t0_ms();
        let t1 = obs.t1_ms();
        if t0 < self.probe_start_ms {
            self.probe_start_ms = t0;
        }
        if t1 > self.probe_end_ms {
            self.probe_end_ms = t1;
        }
        self.observations.push(obs);
    }

    /// Merges another ObservationSet into this one, combining all observations.
    pub fn merge(&mut self, other: ObservationSet) {
        if other.probe_start_ms < self.probe_start_ms {
            self.probe_start_ms = other.probe_start_ms;
        }
        if other.probe_end_ms > self.probe_end_ms {
            self.probe_end_ms = other.probe_end_ms;
        }
        self.observations.extend(other.observations);
    }

    /// Filters observations by type.
    pub fn filter_type(&self, t: ObservationType) -> Vec<&Observation> {
        self.observations
            .iter()
            .filter(|o| o.observation_type() == t)
            .collect()
    }

    /// Returns all TCP observations.
    pub fn tcp_observations(&self) -> Vec<&TcpObservation> {
        self.filter_type(ObservationType::Tcp)
            .iter()
            .filter_map(|o| match o {
                Observation::Tcp(t) => Some(t),
                _ => None,
            })
            .collect()
    }

    /// Returns all TLS observations.
    pub fn tls_observations(&self) -> Vec<&TlsObservation> {
        self.filter_type(ObservationType::Tls)
            .iter()
            .filter_map(|o| match o {
                Observation::Tls(t) => Some(t),
                _ => None,
            })
            .collect()
    }

    /// Returns all DNS observations.
    pub fn dns_observations(&self) -> Vec<&DnsObservation> {
        self.filter_type(ObservationType::Dns)
            .iter()
            .filter_map(|o| match o {
                Observation::Dns(d) => Some(d),
                _ => None,
            })
            .collect()
    }

    /// Returns all HTTP observations.
    pub fn http_observations(&self) -> Vec<&HttpObservation> {
        self.filter_type(ObservationType::Http)
            .iter()
            .filter_map(|o| match o {
                Observation::Http(h) => Some(h),
                _ => None,
            })
            .collect()
    }

    /// Returns the count of failed observations.
    pub fn failure_count(&self) -> usize {
        self.observations.iter().filter(|o| o.is_failure()).count()
    }

    /// Returns the total duration of the probe session in milliseconds.
    pub fn duration_ms(&self) -> u64 {
        self.probe_end_ms.saturating_sub(self.probe_start_ms)
    }

    /// Returns true if all observations succeeded.
    pub fn all_success(&self) -> bool {
        !self.observations.iter().any(|o| o.is_failure())
    }

    /// Serializes the observation set to JSON bytes.
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

/// Returns the current Unix timestamp in milliseconds.
pub fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// TcpObservationBuilder builds a TcpObservation.
#[derive(Default)]
pub struct TcpObservationBuilder {
    local_addr: Option<String>,
    remote_addr: Option<String>,
    hostname: Option<String>,
    port: Option<u16>,
    success: Option<bool>,
    latency_ms: Option<u64>,
    failure: Option<String>,
    reset: bool,
    timeout: bool,
    proxy: bool,
    alpn: Option<String>,
    tls_version: Option<String>,
    tls_cipher: Option<String>,
}

impl TcpObservationBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn local_addr(mut self, addr: String) -> Self {
        self.local_addr = Some(addr);
        self
    }

    pub fn remote_addr(mut self, addr: String) -> Self {
        self.remote_addr = Some(addr);
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn success(mut self, success: bool) -> Self {
        self.success = Some(success);
        self
    }

    pub fn latency_ms(mut self, ms: u64) -> Self {
        self.latency_ms = Some(ms);
        self
    }

    pub fn failure(mut self, f: String) -> Self {
        self.failure = Some(f);
        self
    }

    pub fn reset(mut self, r: bool) -> Self {
        self.reset = r;
        self
    }

    pub fn timeout(mut self, t: bool) -> Self {
        self.timeout = t;
        self
    }

    pub fn build(self) -> Observation {
        let t0 = unix_time_ms();
        let t1 = unix_time_ms();
        Observation::Tcp(TcpObservation {
            local_addr: self.local_addr,
            remote_addr: self.remote_addr,
            hostname: self.hostname,
            port: self.port.unwrap_or(0),
            success: self.success.unwrap_or(false),
            latency_ms: self.latency_ms,
            failure: self.failure,
            reset: self.reset,
            timeout: self.timeout,
            proxy: self.proxy,
            alpn: self.alpn,
            tls_version: self.tls_version,
            tls_cipher: self.tls_cipher,
            t0_ms: t0,
            t1_ms: t1,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_observation_type_discriminator() {
        let obs = TcpObservationBuilder::new()
            .remote_addr("1.2.3.4:443".to_string())
            .port(443)
            .success(true)
            .build();
        assert_eq!(obs.observation_type(), ObservationType::Tcp);
        assert!(!obs.is_failure());
    }

    #[test]
    fn test_observation_set_merge() {
        let mut set1 = ObservationSet::new();
        let obs1 = TcpObservationBuilder::new()
            .remote_addr("1.2.3.4:80".to_string())
            .port(80)
            .success(false)
            .failure("connection_reset".to_string())
            .build();
        set1.add(obs1);

        let mut set2 = ObservationSet::new();
        let obs2 = TcpObservationBuilder::new()
            .remote_addr("5.6.7.8:443".to_string())
            .port(443)
            .success(true)
            .latency_ms(42)
            .build();
        set2.add(obs2);

        set1.merge(set2);
        assert_eq!(set1.observations.len(), 2);
        assert_eq!(set1.failure_count(), 1);
        assert!(!set1.all_success());
    }

    #[test]
    fn test_observation_set_filter_type() {
        let mut set = ObservationSet::new();
        set.add(Observation::Tcp(TcpObservation {
            local_addr: Some("127.0.0.1:0".to_string()),
            remote_addr: Some("1.1.1.1:443".to_string()),
            hostname: None,
            port: 443,
            success: true,
            latency_ms: Some(10),
            failure: None,
            reset: false,
            timeout: false,
            proxy: false,
            alpn: Some("h2".to_string()),
            tls_version: Some("TLS1.3".to_string()),
            tls_cipher: Some("TLS_AES_256_GCM_SHA384".to_string()),
            t0_ms: unix_time_ms(),
            t1_ms: unix_time_ms(),
        }));
        set.add(Observation::Dns(DnsObservation {
            query_name: "example.com".to_string(),
            query_type: "A".to_string(),
            server: Some("8.8.8.8:53".to_string()),
            success: true,
            answers: vec!["93.184.216.34".to_string()],
            cnames: vec![],
            dnssec_valid: false,
            received: true,
            failure: None,
            latency_ms: Some(5),
            doh: false,
            dot: false,
            t0_ms: unix_time_ms(),
            t1_ms: unix_time_ms(),
        }));

        let tcp_obs = set.tcp_observations();
        assert_eq!(tcp_obs.len(), 1);
        assert_eq!(tcp_obs[0].port, 443);

        let dns_obs = set.dns_observations();
        assert_eq!(dns_obs.len(), 1);
        assert_eq!(dns_obs[0].query_name, "example.com");
    }

    #[test]
    fn test_observation_set_duration() {
        let mut set = ObservationSet::new();
        assert_eq!(set.duration_ms(), 0);
        set.probe_end_ms = 1000;
        assert_eq!(set.duration_ms(), 0); // start == end
        set.probe_start_ms = 500;
        assert_eq!(set.duration_ms(), 500);
    }

    #[test]
    fn test_tcp_observation_builder() {
        let obs = TcpObservationBuilder::new()
            .local_addr("10.0.0.1:50000".to_string())
            .remote_addr("8.8.8.8:53".to_string())
            .port(53)
            .success(false)
            .failure("timeout".to_string())
            .timeout(true)
            .build();
        assert!(obs.is_failure());
        if let Observation::Tcp(t) = obs {
            assert_eq!(t.port, 53);
            assert!(t.timeout);
        } else {
            panic!("expected Tcp observation");
        }
    }

    #[test]
    fn test_json_serde() {
        let mut set = ObservationSet::new();
        set.add(Observation::Dns(DnsObservation {
            query_name: "example.com".to_string(),
            query_type: "AAAA".to_string(),
            server: Some("2001:db8::1".to_string()),
            success: true,
            answers: vec!["::1".to_string()],
            cnames: vec![],
            dnssec_valid: true,
            received: true,
            failure: None,
            latency_ms: Some(3),
            doh: false,
            dot: true,
            t0_ms: unix_time_ms(),
            t1_ms: unix_time_ms(),
        }));
        let json = set.to_json().unwrap();
        assert!(!json.is_empty());
        assert!(json.starts_with(b"{"));
    }

    #[test]
    fn test_tls_observation_classification() {
        let obs = Observation::Tls(TlsObservation {
            remote_addr: Some("1.1.1.1:443".to_string()),
            sni: Some("one.one.one.one".to_string()),
            success: false,
            version: None,
            cipher_suite: None,
            cert_fingerprint: None,
            cert_valid: false,
            cert_expiry: None,
            resumed: false,
            intercepted: false,
            failure: Some("certificate_unknown".to_string()),
            ja3: None,
            ja4: None,
            t0_ms: unix_time_ms(),
            t1_ms: unix_time_ms(),
        });
        assert!(obs.is_failure());
        assert_eq!(obs.observation_type(), ObservationType::Tls);
    }
}
