//! # Multi-Core Tunnel Process Supervisor & Log Telemetry Engine
//!
//! Provides multi-core process lifecycle tracking, WSL/stderr noise filtration,
//! interactive OAuth2 URL extraction for cloud storage tunnels, circular ring-buffer
//! log capture, and JSON configuration synthesis for Google Apps Script & Google Drive relays.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

/// Engine architecture type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineType {
    /// Google Apps Script SOCKS5 Relay (GooseRelayVPN protocol)
    AppsScript,
    /// Google Drive API SOCKS5 Storage Tunnel (FlowDriver protocol)
    DriveStorage,
}

/// Execution lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreState {
    Stopped,
    Starting,
    Running,
    Error,
}

/// Log classification severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Info,
    Warn,
    Error,
    OAuth,
}

/// Structured log line entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub level: LogLevel,
    pub message: String,
    pub timestamp_ms: u64,
}

/// OAuth2 authentication flow state for storage-based tunnel backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthState {
    None,
    WaitingForInput,
    Done,
}

/// Checks if a stderr line is informational WSL or virtualized bridge noise.
pub fn is_wsl_noise(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.starts_with("wsl:")
        || lower.contains("localhost proxy")
        || lower.contains("nat mode does not support")
        || lower.contains("not mirrored into wsl")
}

/// Checks if a stderr line matches standard binary INFO patterns from Go runtime or custom loggers.
pub fn is_binary_info_pattern(line: &str) -> bool {
    // GooseRelay patterns
    if line.contains("CARRIER INFO")
        || line.contains("CLIENT INFO")
        || line.contains("SERVER INFO")
        || line.contains("SOCKS INFO")
    {
        return true;
    }
    let lower = line.to_ascii_lowercase();
    if lower.contains("relay returned")
        || lower.contains("non-batch payload")
        || lower.contains("zero-config")
        || lower.contains("flow-data")
        || lower.contains("oauth")
        || lower.contains("trading code")
        || lower.contains("refresh token")
        || lower.contains("google drive")
        || lower.contains("flowdriver")
        || lower.contains("new session")
    {
        return true;
    }

    // Go standard logger format: 2006/01/02 15:04:05 <message>
    if line.len() >= 20 {
        let b = line.as_bytes();
        if b[4] == b'/' && b[7] == b'/' && b[10] == b' ' && b[13] == b':' && b[16] == b':' && b[19] == b' ' {
            if b[0..4].iter().all(|c| c.is_ascii_digit())
                && b[5..7].iter().all(|c| c.is_ascii_digit())
                && b[8..10].iter().all(|c| c.is_ascii_digit())
            {
                return true;
            }
        }
    }
    false
}

/// Checks if a log line represents an active forwarded request or connection.
pub fn is_request_forward_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("poll ok")
        || lower.contains("relay request")
        || lower.contains("script.google.com")
        || lower.contains("urlfetch")
        || lower.contains("new session")
        || lower.contains("relay ok")
        || lower.contains("drive.upload")
        || lower.contains("drive.download")
        || lower.contains("request forwarded")
}

/// Extracts a Google OAuth consent URL if present in the line.
pub fn extract_oauth_url(line: &str) -> Option<String> {
    if let Some(idx) = line.find("https://accounts.google.com/") {
        let rest = &line[idx..];
        let end = rest.find(|c: char| c.is_whitespace() || c == '"' || c == '\'').unwrap_or(rest.len());
        return Some(rest[..end].to_string());
    }
    None
}

/// Classifies a log line, identifying OAuth prompt URLs and filtering stderr noise into Info.
pub fn classify_log_line(line: &str, is_stderr: bool) -> (LogLevel, Option<String>) {
    if let Some(url) = extract_oauth_url(line) {
        return (LogLevel::OAuth, Some(url));
    }
    if is_stderr {
        if is_wsl_noise(line) || is_binary_info_pattern(line) {
            (LogLevel::Info, None)
        } else {
            (LogLevel::Error, None)
        }
    } else {
        (LogLevel::Info, None)
    }
}

/// Circular in-memory ring buffer holding recent log entries.
#[derive(Debug, Clone)]
pub struct CoreLogRingBuffer {
    capacity: usize,
    entries: VecDeque<LogEntry>,
}

impl CoreLogRingBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: if capacity == 0 { 500 } else { capacity },
            entries: VecDeque::with_capacity(capacity),
        }
    }

    pub fn push(&mut self, level: LogLevel, message: String) {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if self.entries.len() >= self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(LogEntry {
            level,
            message,
            timestamp_ms,
        });
    }

    pub fn get_recent(&self, limit: usize) -> Vec<LogEntry> {
        let count = limit.min(self.entries.len());
        self.entries.iter().rev().take(count).rev().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Running request counters for usage and quota accounting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreStatsCounter {
    pub total_requests: u64,
    pub today_requests: u64,
    pub last_reset_timestamp_ms: u64,
}

impl Default for CoreStatsCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl CoreStatsCounter {
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            total_requests: 0,
            today_requests: 0,
            last_reset_timestamp_ms: now,
        }
    }

    pub fn increment(&mut self, delta: u64) {
        self.total_requests = self.total_requests.saturating_add(delta);
        self.today_requests = self.today_requests.saturating_add(delta);
    }

    pub fn reset_daily(&mut self) {
        self.today_requests = 0;
        self.last_reset_timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
    }
}

/// Configuration structure for Google Apps Script SOCKS5 Tunnel Core.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppsScriptCoreConfig {
    pub socks_host: String,
    pub socks_port: u16,
    pub google_host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<serde_json::Value>,
    pub script_keys: Vec<String>,
    pub tunnel_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socks_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socks_pass: Option<String>,
}

impl AppsScriptCoreConfig {
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Configuration structure for Google Drive API Storage SOCKS5 Tunnel Core.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveStorageTransport {
    #[serde(rename = "TargetIP")]
    pub target_ip: String,
    #[serde(rename = "SNI")]
    pub sni: String,
    #[serde(rename = "HostHeader")]
    pub host_header: String,
    #[serde(rename = "InsecureSkipVerify")]
    pub insecure_skip_verify: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveStorageCoreConfig {
    pub listen_addr: String,
    pub storage_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub google_folder_id: Option<String>,
    pub refresh_rate_ms: u32,
    pub flush_rate_ms: u32,
    pub transport: DriveStorageTransport,
}

impl DriveStorageCoreConfig {
    pub fn new_google_drive(
        listen_addr: String,
        google_folder_id: Option<String>,
        refresh_rate_ms: u32,
        flush_rate_ms: u32,
        target_ip: String,
        sni: String,
        host_header: String,
    ) -> Self {
        Self {
            listen_addr,
            storage_type: "google".to_string(),
            google_folder_id,
            refresh_rate_ms,
            flush_rate_ms,
            transport: DriveStorageTransport {
                target_ip,
                sni,
                host_header,
                insecure_skip_verify: false,
            },
        }
    }

    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}
