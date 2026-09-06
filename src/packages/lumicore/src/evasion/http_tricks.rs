//! # HTTP Header Tricks
//!
//! HTTP-level DPI bypass techniques. .
//! 15 techniques for confusing DPI pattern matching.

/// HTTP-level DPI bypass technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpTrick {
    ExtraSpaceAfterGet,
    NewlineBeforeGet,
    TabAfterHost,
    TcpFragmentation,
    TrailingDot,
    MixedCaseHost1,
    MixedCaseHost2,
    UppercaseHostValue,
    NoSpaceAfterColon,
    UnixLineEndings,
    UnusualHeaderOrder,
    ComboFragmentMixedCase,
    Padding7KB,
    Padding15KB,
    Padding21KB,
}

/// Generates all HTTP evasion payloads for a given URL.
pub fn generate_http_payloads(host: &str, path: &str) -> Vec<(HttpTrick, Vec<u8>)> {
    let mut payloads = Vec::new();

    payloads.push((
        HttpTrick::ExtraSpaceAfterGet,
        format!("GET  {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").into_bytes(),
    ));
    payloads.push((
        HttpTrick::NewlineBeforeGet,
        format!("\r\nGET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
            .into_bytes(),
    ));
    payloads.push((
        HttpTrick::TabAfterHost,
        format!("GET {path} HTTP/1.1\r\nHost: {host}\t\r\nConnection: close\r\n\r\n").into_bytes(),
    ));
    payloads.push((
        HttpTrick::TrailingDot,
        format!("GET {path} HTTP/1.1\r\nHost: {host}.\r\nConnection: close\r\n\r\n").into_bytes(),
    ));
    payloads.push((
        HttpTrick::MixedCaseHost1,
        format!("GET {path} HTTP/1.1\r\nhoSt: {host}\r\nConnection: close\r\n\r\n").into_bytes(),
    ));
    payloads.push((
        HttpTrick::MixedCaseHost2,
        format!("GET {path} HTTP/1.1\r\nhOSt: {host}\r\nConnection: close\r\n\r\n").into_bytes(),
    ));
    payloads.push((
        HttpTrick::UppercaseHostValue,
        format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            host.to_uppercase()
        )
        .into_bytes(),
    ));
    payloads.push((
        HttpTrick::NoSpaceAfterColon,
        format!("GET {path} HTTP/1.1\r\nHost:{host}\r\nConnection: close\r\n\r\n").into_bytes(),
    ));
    payloads.push((
        HttpTrick::UnixLineEndings,
        format!("GET {path} HTTP/1.1\nHost: {host}\nConnection: close\n\n").into_bytes(),
    ));
    payloads.push((
        HttpTrick::UnusualHeaderOrder,
        format!("GET {path} HTTP/1.1\r\nConnection: close\r\nHost: {host}\r\n\r\n").into_bytes(),
    ));
    payloads.push((
        HttpTrick::ComboFragmentMixedCase,
        format!("GET {path} HTTP/1.1\r\nhoSt:{host}\r\nConnection: close\r\n\r\n").into_bytes(),
    ));

    // Padding techniques
    let padding = "X-Padding: ".to_string() + &"A".repeat(990) + "\r\n";
    payloads.push((
        HttpTrick::Padding7KB,
        (format!("GET {path} HTTP/1.1\r\n")
            + &padding.repeat(7)
            + &format!("Host: {host}\r\nConnection: close\r\n\r\n"))
            .into_bytes(),
    ));
    payloads.push((
        HttpTrick::Padding15KB,
        (format!("GET {path} HTTP/1.1\r\n")
            + &padding.repeat(15)
            + &format!("Host: {host}\r\nConnection: close\r\n\r\n"))
            .into_bytes(),
    ));
    let padding_21k = "X-Padding: ".to_string() + &"A".repeat(2990) + "\r\n";
    payloads.push((
        HttpTrick::Padding21KB,
        (format!("GET {path} HTTP/1.1\r\n")
            + &padding_21k.repeat(7)
            + &format!("Host: {host}\r\nConnection: close\r\n\r\n"))
            .into_bytes(),
    ));

    payloads
}

use std::collections::HashMap;

#[derive(Clone, Debug, Default)]
pub struct HttpEvasionConfig {
    pub enabled_tricks: Vec<HttpTrick>,
    pub timeout_ms: u32,
    pub follow_redirects: bool,
    pub max_redirects: u16,
    pub proxy_url: Option<String>,
    pub user_agent: String,
    pub custom_headers: HashMap<String, String>,
    pub port_override: Option<u16>,
    pub padding_size_kb: usize,
    pub force_http11: bool,
    pub connection_keepalive: bool,
    pub log_verbosity: String,
    pub max_concurrency: usize,
    pub buffer_size: usize,
    pub verify_ssl: bool,
}

impl HttpEvasionConfig {
    // Getters
    pub fn get_enabled_tricks(&self) -> &[HttpTrick] {
        &self.enabled_tricks
    }
    pub fn get_timeout_ms(&self) -> u32 {
        self.timeout_ms
    }
    pub fn get_follow_redirects(&self) -> bool {
        self.follow_redirects
    }
    pub fn get_max_redirects(&self) -> u16 {
        self.max_redirects
    }
    pub fn get_proxy_url(&self) -> Option<&str> {
        self.proxy_url.as_deref()
    }
    pub fn get_user_agent(&self) -> &str {
        &self.user_agent
    }
    pub fn get_custom_headers(&self) -> &HashMap<String, String> {
        &self.custom_headers
    }
    pub fn get_port_override(&self) -> Option<u16> {
        self.port_override
    }
    pub fn get_padding_size_kb(&self) -> usize {
        self.padding_size_kb
    }
    pub fn get_force_http11(&self) -> bool {
        self.force_http11
    }
    pub fn get_connection_keepalive(&self) -> bool {
        self.connection_keepalive
    }
    pub fn get_log_verbosity(&self) -> &str {
        &self.log_verbosity
    }
    pub fn get_max_concurrency(&self) -> usize {
        self.max_concurrency
    }
    pub fn get_buffer_size(&self) -> usize {
        self.buffer_size
    }
    pub fn get_verify_ssl(&self) -> bool {
        self.verify_ssl
    }

    // Setters
    pub fn set_enabled_tricks(&mut self, val: Vec<HttpTrick>) {
        self.enabled_tricks = val;
    }
    pub fn set_timeout_ms(&mut self, val: u32) {
        self.timeout_ms = val;
    }
    pub fn set_follow_redirects(&mut self, val: bool) {
        self.follow_redirects = val;
    }
    pub fn set_max_redirects(&mut self, val: u16) {
        self.max_redirects = val;
    }
    pub fn set_proxy_url(&mut self, val: Option<String>) {
        self.proxy_url = val;
    }
    pub fn set_user_agent(&mut self, val: String) {
        self.user_agent = val;
    }
    pub fn set_custom_headers(&mut self, val: HashMap<String, String>) {
        self.custom_headers = val;
    }
    pub fn set_port_override(&mut self, val: Option<u16>) {
        self.port_override = val;
    }
    pub fn set_padding_size_kb(&mut self, val: usize) {
        self.padding_size_kb = val;
    }
    pub fn set_force_http11(&mut self, val: bool) {
        self.force_http11 = val;
    }
    pub fn set_connection_keepalive(&mut self, val: bool) {
        self.connection_keepalive = val;
    }
    pub fn set_log_verbosity(&mut self, val: String) {
        self.log_verbosity = val;
    }
    pub fn set_max_concurrency(&mut self, val: usize) {
        self.max_concurrency = val;
    }
    pub fn set_buffer_size(&mut self, val: usize) {
        self.buffer_size = val;
    }
    pub fn set_verify_ssl(&mut self, val: bool) {
        self.verify_ssl = val;
    }

    // Builders
    pub fn with_enabled_tricks(mut self, val: Vec<HttpTrick>) -> Self {
        self.enabled_tricks = val;
        self
    }
    pub fn with_timeout_ms(mut self, val: u32) -> Self {
        self.timeout_ms = val;
        self
    }
    pub fn with_follow_redirects(mut self, val: bool) -> Self {
        self.follow_redirects = val;
        self
    }
    pub fn with_max_redirects(mut self, val: u16) -> Self {
        self.max_redirects = val;
        self
    }
    pub fn with_proxy_url(mut self, val: Option<String>) -> Self {
        self.proxy_url = val;
        self
    }
    pub fn with_user_agent(mut self, val: String) -> Self {
        self.user_agent = val;
        self
    }
    pub fn with_custom_headers(mut self, val: HashMap<String, String>) -> Self {
        self.custom_headers = val;
        self
    }
    pub fn with_port_override(mut self, val: Option<u16>) -> Self {
        self.port_override = val;
        self
    }
    pub fn with_padding_size_kb(mut self, val: usize) -> Self {
        self.padding_size_kb = val;
        self
    }
    pub fn with_force_http11(mut self, val: bool) -> Self {
        self.force_http11 = val;
        self
    }
    pub fn with_connection_keepalive(mut self, val: bool) -> Self {
        self.connection_keepalive = val;
        self
    }
    pub fn with_log_verbosity(mut self, val: String) -> Self {
        self.log_verbosity = val;
        self
    }
    pub fn with_max_concurrency(mut self, val: usize) -> Self {
        self.max_concurrency = val;
        self
    }
    pub fn with_buffer_size(mut self, val: usize) -> Self {
        self.buffer_size = val;
        self
    }
    pub fn with_verify_ssl(mut self, val: bool) -> Self {
        self.verify_ssl = val;
        self
    }

    // List modifiers
    pub fn add_trick(&mut self, val: HttpTrick) {
        self.enabled_tricks.push(val);
    }
    pub fn remove_trick(&mut self, val: HttpTrick) -> bool {
        if let Some(pos) = self.enabled_tricks.iter().position(|&x| x == val) {
            self.enabled_tricks.remove(pos);
            true
        } else {
            false
        }
    }
    pub fn clear_tricks(&mut self) {
        self.enabled_tricks.clear();
    }
    pub fn add_header(&mut self, k: String, v: String) {
        self.custom_headers.insert(k, v);
    }
    pub fn remove_header(&mut self, k: &str) -> Option<String> {
        self.custom_headers.remove(k)
    }
    pub fn clear_headers(&mut self) {
        self.custom_headers.clear();
    }
}

#[derive(Clone, Debug, Default)]
pub struct HttpEvasionReporter {
    pub success_count: u64,
    pub failure_count: u64,
    pub total_latency_ms: f64,
    pub bytes_transferred: u64,
    pub last_status_code: u16,
    pub captive_portal_detected: bool,
    pub redirect_count: u16,
    pub last_error_message: String,
    pub average_latency_ms: f64,
    pub transfer_rate_kbps: f64,
}

impl HttpEvasionReporter {
    // Getters
    pub fn get_success_count(&self) -> u64 {
        self.success_count
    }
    pub fn get_failure_count(&self) -> u64 {
        self.failure_count
    }
    pub fn get_total_latency_ms(&self) -> f64 {
        self.total_latency_ms
    }
    pub fn get_bytes_transferred(&self) -> u64 {
        self.bytes_transferred
    }
    pub fn get_last_status_code(&self) -> u16 {
        self.last_status_code
    }
    pub fn get_captive_portal_detected(&self) -> bool {
        self.captive_portal_detected
    }
    pub fn get_redirect_count(&self) -> u16 {
        self.redirect_count
    }
    pub fn get_last_error_message(&self) -> &str {
        &self.last_error_message
    }
    pub fn get_average_latency_ms(&self) -> f64 {
        self.average_latency_ms
    }
    pub fn get_transfer_rate_kbps(&self) -> f64 {
        self.transfer_rate_kbps
    }

    // Setters
    pub fn set_success_count(&mut self, val: u64) {
        self.success_count = val;
    }
    pub fn set_failure_count(&mut self, val: u64) {
        self.failure_count = val;
    }
    pub fn set_total_latency_ms(&mut self, val: f64) {
        self.total_latency_ms = val;
    }
    pub fn set_bytes_transferred(&mut self, val: u64) {
        self.bytes_transferred = val;
    }
    pub fn set_last_status_code(&mut self, val: u16) {
        self.last_status_code = val;
    }
    pub fn set_captive_portal_detected(&mut self, val: bool) {
        self.captive_portal_detected = val;
    }
    pub fn set_redirect_count(&mut self, val: u16) {
        self.redirect_count = val;
    }
    pub fn set_last_error_message(&mut self, val: String) {
        self.last_error_message = val;
    }
    pub fn set_average_latency_ms(&mut self, val: f64) {
        self.average_latency_ms = val;
    }
    pub fn set_transfer_rate_kbps(&mut self, val: f64) {
        self.transfer_rate_kbps = val;
    }

    // Builders
    pub fn with_success_count(mut self, val: u64) -> Self {
        self.success_count = val;
        self
    }
    pub fn with_failure_count(mut self, val: u64) -> Self {
        self.failure_count = val;
        self
    }
    pub fn with_total_latency_ms(mut self, val: f64) -> Self {
        self.total_latency_ms = val;
        self
    }
    pub fn with_bytes_transferred(mut self, val: u64) -> Self {
        self.bytes_transferred = val;
        self
    }
    pub fn with_last_status_code(mut self, val: u16) -> Self {
        self.last_status_code = val;
        self
    }
    pub fn with_captive_portal_detected(mut self, val: bool) -> Self {
        self.captive_portal_detected = val;
        self
    }
    pub fn with_redirect_count(mut self, val: u16) -> Self {
        self.redirect_count = val;
        self
    }
    pub fn with_last_error_message(mut self, val: String) -> Self {
        self.last_error_message = val;
        self
    }
    pub fn with_average_latency_ms(mut self, val: f64) -> Self {
        self.average_latency_ms = val;
        self
    }
    pub fn with_transfer_rate_kbps(mut self, val: f64) -> Self {
        self.transfer_rate_kbps = val;
        self
    }

    // Recorders
    pub fn record_success(&mut self, latency: f64, bytes: u64) {
        self.success_count += 1;
        self.total_latency_ms += latency;
        self.average_latency_ms = self.total_latency_ms / (self.success_count as f64);
        self.bytes_transferred += bytes;
    }
    pub fn record_failure(&mut self, msg: String) {
        self.failure_count += 1;
        self.last_error_message = msg;
    }
    pub fn record_redirect(&mut self) {
        self.redirect_count += 1;
    }
    pub fn reset_stats(&mut self) {
        self.success_count = 0;
        self.failure_count = 0;
        self.total_latency_ms = 0.0;
        self.bytes_transferred = 0;
        self.last_status_code = 0;
        self.captive_portal_detected = false;
        self.redirect_count = 0;
        self.last_error_message.clear();
        self.average_latency_ms = 0.0;
        self.transfer_rate_kbps = 0.0;
    }
}

#[derive(Clone, Debug, Default)]
pub struct HttpScannerResult {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub latency_ms: f64,
    pub content_length: u64,
    pub censor_type: String,
    pub is_blocked: bool,
    pub redirect_url: String,
    pub matched_signature: String,
    pub ip_address: String,
}

impl HttpScannerResult {
    // Getters
    pub fn get_status(&self) -> u16 {
        self.status
    }
    pub fn get_headers(&self) -> &HashMap<String, String> {
        &self.headers
    }
    pub fn get_body(&self) -> &[u8] {
        &self.body
    }
    pub fn get_latency_ms(&self) -> f64 {
        self.latency_ms
    }
    pub fn get_content_length(&self) -> u64 {
        self.content_length
    }
    pub fn get_censor_type(&self) -> &str {
        &self.censor_type
    }
    pub fn get_is_blocked(&self) -> bool {
        self.is_blocked
    }
    pub fn get_redirect_url(&self) -> &str {
        &self.redirect_url
    }
    pub fn get_matched_signature(&self) -> &str {
        &self.matched_signature
    }
    pub fn get_ip_address(&self) -> &str {
        &self.ip_address
    }

    // Setters
    pub fn set_status(&mut self, val: u16) {
        self.status = val;
    }
    pub fn set_headers(&mut self, val: HashMap<String, String>) {
        self.headers = val;
    }
    pub fn set_body(&mut self, val: Vec<u8>) {
        self.body = val;
    }
    pub fn set_latency_ms(&mut self, val: f64) {
        self.latency_ms = val;
    }
    pub fn set_content_length(&mut self, val: u64) {
        self.content_length = val;
    }
    pub fn set_censor_type(&mut self, val: String) {
        self.censor_type = val;
    }
    pub fn set_is_blocked(&mut self, val: bool) {
        self.is_blocked = val;
    }
    pub fn set_redirect_url(&mut self, val: String) {
        self.redirect_url = val;
    }
    pub fn set_matched_signature(&mut self, val: String) {
        self.matched_signature = val;
    }
    pub fn set_ip_address(&mut self, val: String) {
        self.ip_address = val;
    }

    // Builders
    pub fn with_status(mut self, val: u16) -> Self {
        self.status = val;
        self
    }
    pub fn with_headers(mut self, val: HashMap<String, String>) -> Self {
        self.headers = val;
        self
    }
    pub fn with_body(mut self, val: Vec<u8>) -> Self {
        self.body = val;
        self
    }
    pub fn with_latency_ms(mut self, val: f64) -> Self {
        self.latency_ms = val;
        self
    }
    pub fn with_content_length(mut self, val: u64) -> Self {
        self.content_length = val;
        self
    }
    pub fn with_censor_type(mut self, val: String) -> Self {
        self.censor_type = val;
        self
    }
    pub fn with_is_blocked(mut self, val: bool) -> Self {
        self.is_blocked = val;
        self
    }
    pub fn with_redirect_url(mut self, val: String) -> Self {
        self.redirect_url = val;
        self
    }
    pub fn with_matched_signature(mut self, val: String) -> Self {
        self.matched_signature = val;
        self
    }
    pub fn with_ip_address(mut self, val: String) -> Self {
        self.ip_address = val;
        self
    }

    // List modifiers
    pub fn add_header(&mut self, k: String, v: String) {
        self.headers.insert(k, v);
    }
    pub fn remove_header(&mut self, k: &str) -> Option<String> {
        self.headers.remove(k)
    }
    pub fn clear_headers(&mut self) {
        self.headers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_payloads() {
        let payloads = generate_http_payloads("example.com", "/test");
        assert_eq!(payloads.len(), 14);
    }
}
