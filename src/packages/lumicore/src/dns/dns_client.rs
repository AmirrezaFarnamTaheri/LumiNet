//! DNS client configuration, telemetry, and results structures.

#[derive(Clone, Debug, Default)]
pub struct DnsClientConfig {
    pub resolvers: Vec<String>,
    pub timeout_ms: u32,
    pub retry_count: u8,
    pub enable_dnssec: bool,
    pub enable_edns: bool,
    pub port: u16,
    pub protocol: String,
    pub search_domains: Vec<String>,
    pub max_concurrency: usize,
    pub cache_enabled: bool,
    pub cache_ttl_sec: u32,
    pub use_tcp_fallback: bool,
    pub recursion_desired: bool,
    pub edns_subnet: Option<String>,
    pub log_verbosity: String,
}

impl DnsClientConfig {
    // Getters
    pub fn get_resolvers(&self) -> &[String] {
        &self.resolvers
    }
    pub fn get_timeout_ms(&self) -> u32 {
        self.timeout_ms
    }
    pub fn get_retry_count(&self) -> u8 {
        self.retry_count
    }
    pub fn get_enable_dnssec(&self) -> bool {
        self.enable_dnssec
    }
    pub fn get_enable_edns(&self) -> bool {
        self.enable_edns
    }
    pub fn get_port(&self) -> u16 {
        self.port
    }
    pub fn get_protocol(&self) -> &str {
        &self.protocol
    }
    pub fn get_search_domains(&self) -> &[String] {
        &self.search_domains
    }
    pub fn get_max_concurrency(&self) -> usize {
        self.max_concurrency
    }
    pub fn get_cache_enabled(&self) -> bool {
        self.cache_enabled
    }
    pub fn get_cache_ttl_sec(&self) -> u32 {
        self.cache_ttl_sec
    }
    pub fn get_use_tcp_fallback(&self) -> bool {
        self.use_tcp_fallback
    }
    pub fn get_recursion_desired(&self) -> bool {
        self.recursion_desired
    }
    pub fn get_edns_subnet(&self) -> Option<&str> {
        self.edns_subnet.as_deref()
    }
    pub fn get_log_verbosity(&self) -> &str {
        &self.log_verbosity
    }

    // Setters
    pub fn set_resolvers(&mut self, val: Vec<String>) {
        self.resolvers = val;
    }
    pub fn set_timeout_ms(&mut self, val: u32) {
        self.timeout_ms = val;
    }
    pub fn set_retry_count(&mut self, val: u8) {
        self.retry_count = val;
    }
    pub fn set_enable_dnssec(&mut self, val: bool) {
        self.enable_dnssec = val;
    }
    pub fn set_enable_edns(&mut self, val: bool) {
        self.enable_edns = val;
    }
    pub fn set_port(&mut self, val: u16) {
        self.port = val;
    }
    pub fn set_protocol(&mut self, val: String) {
        self.protocol = val;
    }
    pub fn set_search_domains(&mut self, val: Vec<String>) {
        self.search_domains = val;
    }
    pub fn set_max_concurrency(&mut self, val: usize) {
        self.max_concurrency = val;
    }
    pub fn set_cache_enabled(&mut self, val: bool) {
        self.cache_enabled = val;
    }
    pub fn set_cache_ttl_sec(&mut self, val: u32) {
        self.cache_ttl_sec = val;
    }
    pub fn set_use_tcp_fallback(&mut self, val: bool) {
        self.use_tcp_fallback = val;
    }
    pub fn set_recursion_desired(&mut self, val: bool) {
        self.recursion_desired = val;
    }
    pub fn set_edns_subnet(&mut self, val: Option<String>) {
        self.edns_subnet = val;
    }
    pub fn set_log_verbosity(&mut self, val: String) {
        self.log_verbosity = val;
    }

    // Builders
    pub fn with_resolvers(mut self, val: Vec<String>) -> Self {
        self.resolvers = val;
        self
    }
    pub fn with_timeout_ms(mut self, val: u32) -> Self {
        self.timeout_ms = val;
        self
    }
    pub fn with_retry_count(mut self, val: u8) -> Self {
        self.retry_count = val;
        self
    }
    pub fn with_enable_dnssec(mut self, val: bool) -> Self {
        self.enable_dnssec = val;
        self
    }
    pub fn with_enable_edns(mut self, val: bool) -> Self {
        self.enable_edns = val;
        self
    }
    pub fn with_port(mut self, val: u16) -> Self {
        self.port = val;
        self
    }
    pub fn with_protocol(mut self, val: String) -> Self {
        self.protocol = val;
        self
    }
    pub fn with_search_domains(mut self, val: Vec<String>) -> Self {
        self.search_domains = val;
        self
    }
    pub fn with_max_concurrency(mut self, val: usize) -> Self {
        self.max_concurrency = val;
        self
    }
    pub fn with_cache_enabled(mut self, val: bool) -> Self {
        self.cache_enabled = val;
        self
    }
    pub fn with_cache_ttl_sec(mut self, val: u32) -> Self {
        self.cache_ttl_sec = val;
        self
    }
    pub fn with_use_tcp_fallback(mut self, val: bool) -> Self {
        self.use_tcp_fallback = val;
        self
    }
    pub fn with_recursion_desired(mut self, val: bool) -> Self {
        self.recursion_desired = val;
        self
    }
    pub fn with_edns_subnet(mut self, val: Option<String>) -> Self {
        self.edns_subnet = val;
        self
    }
    pub fn with_log_verbosity(mut self, val: String) -> Self {
        self.log_verbosity = val;
        self
    }

    // List modifiers
    pub fn add_resolver(&mut self, val: String) {
        self.resolvers.push(val);
    }
    pub fn remove_resolver(&mut self, val: &str) -> bool {
        if let Some(pos) = self.resolvers.iter().position(|x| x == val) {
            self.resolvers.remove(pos);
            true
        } else {
            false
        }
    }
    pub fn clear_resolvers(&mut self) {
        self.resolvers.clear();
    }
    pub fn add_search_domain(&mut self, val: String) {
        self.search_domains.push(val);
    }
    pub fn remove_search_domain(&mut self, val: &str) -> bool {
        if let Some(pos) = self.search_domains.iter().position(|x| x == val) {
            self.search_domains.remove(pos);
            true
        } else {
            false
        }
    }
    pub fn clear_search_domains(&mut self) {
        self.search_domains.clear();
    }
}

#[derive(Clone, Debug, Default)]
pub struct DnsClientReporter {
    pub queries_sent: u64,
    pub responses_received: u64,
    pub timeouts_count: u64,
    pub errors_count: u64,
    pub total_latency_ms: f64,
    pub average_latency_ms: f64,
    pub dnssec_validations: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub last_error_message: String,
}

impl DnsClientReporter {
    // Getters
    pub fn get_queries_sent(&self) -> u64 {
        self.queries_sent
    }
    pub fn get_responses_received(&self) -> u64 {
        self.responses_received
    }
    pub fn get_timeouts_count(&self) -> u64 {
        self.timeouts_count
    }
    pub fn get_errors_count(&self) -> u64 {
        self.errors_count
    }
    pub fn get_total_latency_ms(&self) -> f64 {
        self.total_latency_ms
    }
    pub fn get_average_latency_ms(&self) -> f64 {
        self.average_latency_ms
    }
    pub fn get_dnssec_validations(&self) -> u64 {
        self.dnssec_validations
    }
    pub fn get_cache_hits(&self) -> u64 {
        self.cache_hits
    }
    pub fn get_cache_misses(&self) -> u64 {
        self.cache_misses
    }
    pub fn get_last_error_message(&self) -> &str {
        &self.last_error_message
    }

    // Setters
    pub fn set_queries_sent(&mut self, val: u64) {
        self.queries_sent = val;
    }
    pub fn set_responses_received(&mut self, val: u64) {
        self.responses_received = val;
    }
    pub fn set_timeouts_count(&mut self, val: u64) {
        self.timeouts_count = val;
    }
    pub fn set_errors_count(&mut self, val: u64) {
        self.errors_count = val;
    }
    pub fn set_total_latency_ms(&mut self, val: f64) {
        self.total_latency_ms = val;
    }
    pub fn set_average_latency_ms(&mut self, val: f64) {
        self.average_latency_ms = val;
    }
    pub fn set_dnssec_validations(&mut self, val: u64) {
        self.dnssec_validations = val;
    }
    pub fn set_cache_hits(&mut self, val: u64) {
        self.cache_hits = val;
    }
    pub fn set_cache_misses(&mut self, val: u64) {
        self.cache_misses = val;
    }
    pub fn set_last_error_message(&mut self, val: String) {
        self.last_error_message = val;
    }

    // Builders
    pub fn with_queries_sent(mut self, val: u64) -> Self {
        self.queries_sent = val;
        self
    }
    pub fn with_responses_received(mut self, val: u64) -> Self {
        self.responses_received = val;
        self
    }
    pub fn with_timeouts_count(mut self, val: u64) -> Self {
        self.timeouts_count = val;
        self
    }
    pub fn with_errors_count(mut self, val: u64) -> Self {
        self.errors_count = val;
        self
    }
    pub fn with_total_latency_ms(mut self, val: f64) -> Self {
        self.total_latency_ms = val;
        self
    }
    pub fn with_average_latency_ms(mut self, val: f64) -> Self {
        self.average_latency_ms = val;
        self
    }
    pub fn with_dnssec_validations(mut self, val: u64) -> Self {
        self.dnssec_validations = val;
        self
    }
    pub fn with_cache_hits(mut self, val: u64) -> Self {
        self.cache_hits = val;
        self
    }
    pub fn with_cache_misses(mut self, val: u64) -> Self {
        self.cache_misses = val;
        self
    }
    pub fn with_last_error_message(mut self, val: String) -> Self {
        self.last_error_message = val;
        self
    }

    // Recorders
    pub fn record_query(&mut self) {
        self.queries_sent += 1;
    }
    pub fn record_response(&mut self, latency: f64) {
        self.responses_received += 1;
        self.total_latency_ms += latency;
        self.average_latency_ms = self.total_latency_ms / (self.responses_received as f64);
    }
    pub fn record_timeout(&mut self) {
        self.timeouts_count += 1;
    }
    pub fn record_error(&mut self, msg: String) {
        self.errors_count += 1;
        self.last_error_message = msg;
    }
    pub fn record_cache_hit(&mut self) {
        self.cache_hits += 1;
    }
    pub fn record_cache_miss(&mut self) {
        self.cache_misses += 1;
    }
    pub fn reset_stats(&mut self) {
        self.queries_sent = 0;
        self.responses_received = 0;
        self.timeouts_count = 0;
        self.errors_count = 0;
        self.total_latency_ms = 0.0;
        self.average_latency_ms = 0.0;
        self.dnssec_validations = 0;
        self.cache_hits = 0;
        self.cache_misses = 0;
        self.last_error_message.clear();
    }
}

#[derive(Clone, Debug, Default)]
pub struct DnsClientResult {
    pub domain: String,
    pub resolved_ips: Vec<String>,
    pub success: bool,
    pub latency_ms: f64,
    pub ttl: u32,
    pub rcode: u8,
    pub authoritative: bool,
    pub recursive: bool,
    pub dnssec_ok: bool,
    pub answers_count: usize,
    pub cname_chain: Vec<String>,
    pub raw_response: Vec<u8>,
    pub server_ip: String,
    pub query_type: String,
    pub query_class: String,
}

impl DnsClientResult {
    // Getters
    pub fn get_domain(&self) -> &str {
        &self.domain
    }
    pub fn get_resolved_ips(&self) -> &[String] {
        &self.resolved_ips
    }
    pub fn get_success(&self) -> bool {
        self.success
    }
    pub fn get_latency_ms(&self) -> f64 {
        self.latency_ms
    }
    pub fn get_ttl(&self) -> u32 {
        self.ttl
    }
    pub fn get_rcode(&self) -> u8 {
        self.rcode
    }
    pub fn get_authoritative(&self) -> bool {
        self.authoritative
    }
    pub fn get_recursive(&self) -> bool {
        self.recursive
    }
    pub fn get_dnssec_ok(&self) -> bool {
        self.dnssec_ok
    }
    pub fn get_answers_count(&self) -> usize {
        self.answers_count
    }
    pub fn get_cname_chain(&self) -> &[String] {
        &self.cname_chain
    }
    pub fn get_raw_response(&self) -> &[u8] {
        &self.raw_response
    }
    pub fn get_server_ip(&self) -> &str {
        &self.server_ip
    }
    pub fn get_query_type(&self) -> &str {
        &self.query_type
    }
    pub fn get_query_class(&self) -> &str {
        &self.query_class
    }

    // Setters
    pub fn set_domain(&mut self, val: String) {
        self.domain = val;
    }
    pub fn set_resolved_ips(&mut self, val: Vec<String>) {
        self.resolved_ips = val;
    }
    pub fn set_success(&mut self, val: bool) {
        self.success = val;
    }
    pub fn set_latency_ms(&mut self, val: f64) {
        self.latency_ms = val;
    }
    pub fn set_ttl(&mut self, val: u32) {
        self.ttl = val;
    }
    pub fn set_rcode(&mut self, val: u8) {
        self.rcode = val;
    }
    pub fn set_authoritative(&mut self, val: bool) {
        self.authoritative = val;
    }
    pub fn set_recursive(&mut self, val: bool) {
        self.recursive = val;
    }
    pub fn set_dnssec_ok(&mut self, val: bool) {
        self.dnssec_ok = val;
    }
    pub fn set_answers_count(&mut self, val: usize) {
        self.answers_count = val;
    }
    pub fn set_cname_chain(&mut self, val: Vec<String>) {
        self.cname_chain = val;
    }
    pub fn set_raw_response(&mut self, val: Vec<u8>) {
        self.raw_response = val;
    }
    pub fn set_server_ip(&mut self, val: String) {
        self.server_ip = val;
    }
    pub fn set_query_type(&mut self, val: String) {
        self.query_type = val;
    }
    pub fn set_query_class(&mut self, val: String) {
        self.query_class = val;
    }

    // Builders
    pub fn with_domain(mut self, val: String) -> Self {
        self.domain = val;
        self
    }
    pub fn with_resolved_ips(mut self, val: Vec<String>) -> Self {
        self.resolved_ips = val;
        self
    }
    pub fn with_success(mut self, val: bool) -> Self {
        self.success = val;
        self
    }
    pub fn with_latency_ms(mut self, val: f64) -> Self {
        self.latency_ms = val;
        self
    }
    pub fn with_ttl(mut self, val: u32) -> Self {
        self.ttl = val;
        self
    }
    pub fn with_rcode(mut self, val: u8) -> Self {
        self.rcode = val;
        self
    }
    pub fn with_authoritative(mut self, val: bool) -> Self {
        self.authoritative = val;
        self
    }
    pub fn with_recursive(mut self, val: bool) -> Self {
        self.recursive = val;
        self
    }
    pub fn with_dnssec_ok(mut self, val: bool) -> Self {
        self.dnssec_ok = val;
        self
    }
    pub fn with_answers_count(mut self, val: usize) -> Self {
        self.answers_count = val;
        self
    }
    pub fn with_cname_chain(mut self, val: Vec<String>) -> Self {
        self.cname_chain = val;
        self
    }
    pub fn with_raw_response(mut self, val: Vec<u8>) -> Self {
        self.raw_response = val;
        self
    }
    pub fn with_server_ip(mut self, val: String) -> Self {
        self.server_ip = val;
        self
    }
    pub fn with_query_type(mut self, val: String) -> Self {
        self.query_type = val;
        self
    }
    pub fn with_query_class(mut self, val: String) -> Self {
        self.query_class = val;
        self
    }

    // List modifiers
    pub fn add_resolved_ip(&mut self, val: String) {
        self.resolved_ips.push(val);
    }
    pub fn remove_resolved_ip(&mut self, val: &str) -> bool {
        if let Some(pos) = self.resolved_ips.iter().position(|x| x == val) {
            self.resolved_ips.remove(pos);
            true
        } else {
            false
        }
    }
    pub fn clear_resolved_ips(&mut self) {
        self.resolved_ips.clear();
    }
    pub fn add_cname(&mut self, val: String) {
        self.cname_chain.push(val);
    }
    pub fn remove_cname(&mut self, val: &str) -> bool {
        if let Some(pos) = self.cname_chain.iter().position(|x| x == val) {
            self.cname_chain.remove(pos);
            true
        } else {
            false
        }
    }
    pub fn clear_cname_chain(&mut self) {
        self.cname_chain.clear();
    }

    // Operations
    pub fn new() -> Self {
        Self::default()
    }
    pub fn is_authoritative(&self) -> bool {
        self.authoritative
    }
    pub fn has_answers(&self) -> bool {
        self.answers_count > 0
    }
    pub fn get_primary_ip(&self) -> Option<&str> {
        self.resolved_ips.first().map(|x| x.as_str())
    }
    pub fn validate_result(&self) -> bool {
        self.success && !self.resolved_ips.is_empty()
    }
    pub fn get_latency_duration(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.latency_ms as u64)
    }
}
