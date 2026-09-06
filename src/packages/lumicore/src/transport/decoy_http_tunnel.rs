// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! # HTTP Decoy Encrypted Tunnel Protocol
//!
//! Pure Rust implementation of HTTP request obfuscation and encrypted tunnel framing
//! or raw TCP) are hex-encoded, AES-256-CBC encrypted with an ephemeral IV, Base64 serialized,
//! and transported within plausible decoy HTTP/1.1 requests disguised as traffic to arbitrary
//! configurable web endpoints.

use std::fmt;
use std::str::FromStr;
use std::string::ToString;

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::Aes256;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use cbc::{Decryptor, Encryptor};
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Buffer size limit for single HTTP frame transfers.
pub const DECOY_DEFAULT_BUFFER_SIZE: usize = 65536;
/// Default timeout in seconds for idle sessions.
pub const DECOY_DEFAULT_TIMEOUT_SEC: u16 = 10;
/// Default pull timeout in milliseconds for polling server-side available data.
pub const DECOY_DEFAULT_PULL_TIMEOUT_MS: u16 = 1;

/// Errors that can occur during decoy tunnel framing, encoding, decoding, or cryptography.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecoyTunnelError {
    #[error("I/O buffer too short or incomplete packet")]
    ShortBuffer,
    #[error("Invalid HTTP header or body format")]
    InvalidHttpFormat,
    #[error("Base64 decoding failed: {0}")]
    Base64Error(String),
    #[error("Hex encoding/decoding failed")]
    HexError,
    #[error("Encryption failed")]
    EncryptionError,
    #[error("Decryption failed or invalid key")]
    DecryptionError,
    #[error("Missing required HTTP header: {0}")]
    MissingHeader(String),
    #[error("Invalid or unsupported decoy action: {0}")]
    InvalidAction(String),
    #[error("Invalid configuration: {0}")]
    ConfigError(String),
}

/// Tunnel protocol actions dispatched between agent and server endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecoyAction {
    /// Establishes or opens a new tunnel session to the target destination.
    Open,
    /// Forwards an isolated one-off HTTP request through the remote server.
    Request,
    /// Sends encrypted data payload to an active session.
    Send,
    /// Polls or receives available buffered data from an active session.
    Recv,
    /// Closes and releases an active session on the remote server.
    Close,
    /// Custom action extension.
    Custom(String),
}

impl DecoyAction {
    pub fn as_str(&self) -> &str {
        match self {
            DecoyAction::Open => "open",
            DecoyAction::Request => "request",
            DecoyAction::Send => "send",
            DecoyAction::Recv => "recv",
            DecoyAction::Close => "close",
            DecoyAction::Custom(s) => s.as_str(),
        }
    }
}

impl FromStr for DecoyAction {
    type Err = DecoyTunnelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "open" => Ok(DecoyAction::Open),
            "request" => Ok(DecoyAction::Request),
            "send" => Ok(DecoyAction::Send),
            "recv" => Ok(DecoyAction::Recv),
            "close" => Ok(DecoyAction::Close),
            other => {
                if other.is_empty() {
                    Err(DecoyTunnelError::InvalidAction("Empty action".into()))
                } else {
                    Ok(DecoyAction::Custom(other.to_string()))
                }
            }
        }
    }
}

impl fmt::Display for DecoyAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Configuration governing decoy HTTP framing, encryption token, and decoy endpoints.
#[derive(Debug, Clone)]
pub struct DecoyTunnelConfig {
    /// Pre-shared authentication/encryption token string.
    pub token: String,
    /// List of decoy hostnames/URLs to simulate.
    pub fake_urls: Vec<String>,
    /// Permitted or randomized HTTP methods (e.g. GET, POST, PUT).
    pub methods: Vec<String>,
    /// Decoy API endpoints (e.g. api, login, user, update).
    pub endpoints: Vec<String>,
    /// Disguised User-Agent string.
    pub user_agent: String,
    /// HTTP version string (default "1.1").
    pub http_version: String,
    /// Maximum frame buffer size in bytes.
    pub buffer_size: usize,
    /// Whether persistent HTTP keep-alive connections are enabled.
    pub connection_reuse: bool,
    /// Whether direct TCP/TLS tunnel streaming is enabled.
    pub tunnel_enable: bool,
    /// Socket I/O timeout in seconds.
    pub timeout_sec: u16,
    /// Polling pull timeout in milliseconds.
    pub pull_timeout_ms: u16,
}

impl Default for DecoyTunnelConfig {
    fn default() -> Self {
        Self {
            token: "af445adb-2434-4975-9445-2c1b2231".to_string(),
            fake_urls: vec![
                "nipo.ciron.net".to_string(),
                "sudoer.ir".to_string(),
                "sudoer.net".to_string(),
                "google.com".to_string(),
                "cloudflare.com".to_string(),
            ],
            methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
            ],
            endpoints: vec![
                "api".to_string(),
                "login".to_string(),
                "user".to_string(),
                "update".to_string(),
            ],
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0".to_string(),
            http_version: "1.1".to_string(),
            buffer_size: DECOY_DEFAULT_BUFFER_SIZE,
            connection_reuse: true,
            tunnel_enable: false,
            timeout_sec: DECOY_DEFAULT_TIMEOUT_SEC,
            pull_timeout_ms: DECOY_DEFAULT_PULL_TIMEOUT_MS,
        }
    }
}

impl DecoyTunnelConfig {
    /// Validates the configuration parameters.
    pub fn validate(&self) -> Result<(), DecoyTunnelError> {
        if self.token.is_empty() {
            return Err(DecoyTunnelError::ConfigError("Token cannot be empty".into()));
        }
        if self.fake_urls.is_empty() {
            return Err(DecoyTunnelError::ConfigError(
                "At least one fakeUrl must be defined".into(),
            ));
        }
        if self.methods.is_empty() {
            return Err(DecoyTunnelError::ConfigError(
                "At least one HTTP method must be defined".into(),
            ));
        }
        if self.endpoints.is_empty() {
            return Err(DecoyTunnelError::ConfigError(
                "At least one endpoint must be defined".into(),
            ));
        }
        if self.buffer_size == 0 || self.buffer_size > 65536 {
            return Err(DecoyTunnelError::ConfigError(
                "bufferSize must be between 1 and 65536".into(),
            ));
        }
        Ok(())
    }

    /// Derives a consistent 32-byte AES key from the configured token.
    /// If token is exactly 32 bytes, uses it directly; otherwise calculates SHA-256(token).
    pub fn derive_aes_key(&self) -> [u8; 32] {
        if self.token.as_bytes().len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(self.token.as_bytes());
            key
        } else {
            let mut hasher = Sha256::new();
            hasher.update(self.token.as_bytes());
            let result = hasher.finalize();
            let mut key = [0u8; 32];
            key.copy_from_slice(&result);
            key
        }
    }

    /// Selects a deterministic fake URL based on seed/hash, or picks the first.
    pub fn select_fake_url(&self, seed: usize) -> &str {
        if self.fake_urls.is_empty() {
            "cloudflare.com"
        } else {
            &self.fake_urls[seed % self.fake_urls.len()]
        }
    }

    /// Strips scheme and path to provide a clean Host header value.
    pub fn clean_host_header(&self, fake_url: &str) -> String {
        let mut host = fake_url;
        if let Some(pos) = host.find("://") {
            host = &host[pos + 3..];
        }
        if let Some(pos) = host.find('/') {
            host = &host[..pos];
        }
        host.to_string()
    }

    /// Selects an HTTP method based on seed/hash.
    pub fn select_method(&self, seed: usize) -> &str {
        if self.methods.is_empty() {
            "POST"
        } else {
            &self.methods[seed % self.methods.len()]
        }
    }

    /// Selects an endpoint based on seed/hash.
    pub fn select_endpoint(&self, seed: usize) -> &str {
        if self.endpoints.is_empty() {
            "api"
        } else {
            &self.endpoints[seed % self.endpoints.len()]
        }
    }
}

/// Cryptographic envelope providing AES-256-CBC encryption, decryption, hex, and base64 transforms.
pub struct DecoyEnvelope;

impl DecoyEnvelope {
    /// Encrypts plaintext using AES-256-CBC with PKCS#7 padding.
    /// Prepends the 16-byte randomly generated IV to the returned ciphertext:
    /// `[16-byte IV][Ciphertext]`.
    pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, DecoyTunnelError> {
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);

        let cipher = Encryptor::<Aes256>::new(key.into(), (&iv).into());
        let block_size = 16;
        let pad_len = block_size - (plaintext.len() % block_size);
        let mut buf = vec![0u8; plaintext.len() + pad_len];
        buf[..plaintext.len()].copy_from_slice(plaintext);

        let ciphertext_ref = cipher
            .encrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buf, plaintext.len())
            .map_err(|_| DecoyTunnelError::EncryptionError)?;

        let mut output = Vec::with_capacity(16 + ciphertext_ref.len());
        output.extend_from_slice(&iv);
        output.extend_from_slice(ciphertext_ref);
        Ok(output)
    }

    /// Decrypts `[16-byte IV][Ciphertext]` using AES-256-CBC with PKCS#7 padding.
    pub fn decrypt(data_with_iv: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, DecoyTunnelError> {
        if data_with_iv.len() < 32 {
            return Err(DecoyTunnelError::ShortBuffer);
        }

        let (iv, ciphertext) = data_with_iv.split_at(16);
        let cipher = Decryptor::<Aes256>::new(key.into(), iv.into());
        let mut buf = ciphertext.to_vec();

        let plaintext_ref = cipher
            .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buf)
            .map_err(|_| DecoyTunnelError::DecryptionError)?;

        Ok(plaintext_ref.to_vec())
    }

    /// Encodes a byte slice into a lowercase hexadecimal string.
    pub fn encode_hex(bytes: &[u8]) -> String {
        let mut hex = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            use core::fmt::Write;
            let _ = write!(hex, "{:02x}", b);
        }
        hex
    }

    /// Decodes a hexadecimal string back into raw bytes.
    pub fn decode_hex(hex_str: &str) -> Result<Vec<u8>, DecoyTunnelError> {
        let trimmed = hex_str.trim();
        if trimmed.len() % 2 != 0 {
            return Err(DecoyTunnelError::HexError);
        }
        let mut bytes = Vec::with_capacity(trimmed.len() / 2);
        for i in (0..trimmed.len()).step_by(2) {
            let byte_slice = &trimmed[i..i + 2];
            let byte = u8::from_str_radix(byte_slice, 16).map_err(|_| DecoyTunnelError::HexError)?;
            bytes.push(byte);
        }
        Ok(bytes)
    }

    /// Base64 encodes binary data.
    pub fn encode_base64(bytes: &[u8]) -> String {
        BASE64_STANDARD.encode(bytes)
    }

    /// Base64 decodes string data.
    pub fn decode_base64(b64_str: &str) -> Result<Vec<u8>, DecoyTunnelError> {
        BASE64_STANDARD
            .decode(b64_str.trim().as_bytes())
            .map_err(|e| DecoyTunnelError::Base64Error(e.to_string()))
    }
}

/// Parsed representation of an inbound decoy HTTP request.
#[derive(Debug, Clone)]
pub struct DecoyHttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub host: String,
    pub user_agent: String,
    pub session_id: String,
    pub action: DecoyAction,
    pub content_length: usize,
    pub keep_alive: bool,
    pub raw_headers: Vec<(String, String)>,
    pub raw_body: Vec<u8>,
}

/// Parsed representation of an inbound decoy HTTP response.
#[derive(Debug, Clone)]
pub struct DecoyHttpResponse {
    pub version: String,
    pub status_code: u16,
    pub status_text: String,
    pub content_length: usize,
    pub keep_alive: bool,
    pub raw_headers: Vec<(String, String)>,
    pub raw_body: Vec<u8>,
}

/// Encoder and decoder for decoy HTTP tunnel transactions.
pub struct DecoyHttpCodec;

impl DecoyHttpCodec {
    /// Formats an obfuscated HTTP request from an agent to the server.
    ///
    /// The inner payload is hex-encoded, AES-256-CBC encrypted, Base64 serialized,
    /// and wrapped in a decoy HTTP/1.1 request matching upstream NipoVPN behavior.
    pub fn encode_agent_request(
        config: &DecoyTunnelConfig,
        session_id: &str,
        action: DecoyAction,
        inner_payload: &[u8],
        seed: usize,
    ) -> Result<Vec<u8>, DecoyTunnelError> {
        let key = config.derive_aes_key();

        // 1. Hex-encode the raw payload
        let hex_payload = DecoyEnvelope::encode_hex(inner_payload);

        // 2. Encrypt hex string with AES-256-CBC
        let encrypted = DecoyEnvelope::encrypt(hex_payload.as_bytes(), &key)?;

        // 3. Base64 encode encrypted bytes
        let inner_request_b64 = DecoyEnvelope::encode_base64(&encrypted);

        let fake_url = config.select_fake_url(seed);
        let host_header = config.clean_host_header(fake_url);
        let method = config.select_method(seed);
        let endpoint = config.select_endpoint(seed);

        let conn_str = if config.connection_reuse || action == DecoyAction::Open {
            "keep-alive"
        } else {
            "close"
        };

        let request_str = format!(
            "{} /{} HTTP/{}\r\n\
             Host: {}\r\n\
             User-Agent: {}\r\n\
             Accept: */*\r\n\
             Content-Type: application/text\r\n\
             X-Nipo-Session: {}\r\n\
             X-Nipo-Action: {}\r\n\
             Content-Length: {}\r\n\
             Connection: {}\r\n\
             \r\n\
             {}",
            method,
            endpoint,
            config.http_version,
            host_header,
            config.user_agent,
            session_id,
            action.as_str(),
            inner_request_b64.len(),
            conn_str,
            inner_request_b64
        );

        Ok(request_str.into_bytes())
    }

    /// Decodes an obfuscated HTTP request received by the server, decrypts the payload,
    /// and unpacks the original inner byte stream.
    pub fn decode_server_request(
        config: &DecoyTunnelConfig,
        raw_http: &[u8],
    ) -> Result<(DecoyHttpRequest, Vec<u8>), DecoyTunnelError> {
        let raw_str = core::str::from_utf8(raw_http)
            .map_err(|_| DecoyTunnelError::InvalidHttpFormat)?;

        let header_end = raw_str
            .find("\r\n\r\n")
            .ok_or(DecoyTunnelError::ShortBuffer)?;
        let header_part = &raw_str[..header_end];
        let body_part = &raw_str[header_end + 4..];

        let mut lines = header_part.split("\r\n");
        let request_line = lines.next().ok_or(DecoyTunnelError::InvalidHttpFormat)?;
        let req_parts: Vec<&str> = request_line.split_whitespace().collect();
        if req_parts.len() < 3 {
            return Err(DecoyTunnelError::InvalidHttpFormat);
        }

        let method = req_parts[0].to_string();
        let path = req_parts[1].to_string();
        let version = req_parts[2].replace("HTTP/", "");

        let mut host = String::new();
        let mut user_agent = String::new();
        let mut session_id = String::new();
        let mut action_str = String::new();
        let mut content_length = 0usize;
        let mut keep_alive = true;
        let mut raw_headers = Vec::new();

        for line in lines {
            if line.is_empty() {
                continue;
            }
            if let Some(colon) = line.find(':') {
                let name = line[..colon].trim().to_ascii_lowercase();
                let val = line[colon + 1..].trim().to_string();

                match name.as_str() {
                    "host" => host = val.clone(),
                    "user-agent" => user_agent = val.clone(),
                    "x-nipo-session" => session_id = val.clone(),
                    "x-nipo-action" => action_str = val.clone(),
                    "content-length" => {
                        content_length = val.parse::<usize>().unwrap_or(0);
                    }
                    "connection" => {
                        keep_alive = val.to_ascii_lowercase().contains("keep-alive");
                    }
                    _ => {}
                }
                raw_headers.push((name, val));
            }
        }

        if action_str.is_empty() {
            return Err(DecoyTunnelError::MissingHeader("X-Nipo-Action".into()));
        }

        let action = DecoyAction::from_str(&action_str)?;
        let key = config.derive_aes_key();

        // Check body length
        let body_str = if body_part.len() > content_length && content_length > 0 {
            &body_part[..content_length]
        } else {
            body_part
        };

        // Decrypt payload if present
        let decrypted_payload = if !body_str.trim().is_empty() {
            let encrypted = DecoyEnvelope::decode_base64(body_str)?;
            let hex_bytes = DecoyEnvelope::decrypt(&encrypted, &key)?;
            let hex_str = core::str::from_utf8(&hex_bytes)
                .map_err(|_| DecoyTunnelError::InvalidHttpFormat)?;
            DecoyEnvelope::decode_hex(hex_str)?
        } else {
            Vec::new()
        };

        let parsed_req = DecoyHttpRequest {
            method,
            path,
            version,
            host,
            user_agent,
            session_id,
            action,
            content_length,
            keep_alive,
            raw_headers,
            raw_body: body_str.as_bytes().to_vec(),
        };

        Ok((parsed_req, decrypted_payload))
    }

    /// Formats an encrypted HTTP response from the server back to the agent.
    pub fn encode_server_response(
        config: &DecoyTunnelConfig,
        status_code: u16,
        status_text: &str,
        plain_body: &[u8],
        keep_alive: bool,
    ) -> Result<Vec<u8>, DecoyTunnelError> {
        let key = config.derive_aes_key();

        let encrypted_body = if !plain_body.is_empty() {
            DecoyEnvelope::encrypt(plain_body, &key)?
        } else {
            Vec::new()
        };

        let conn_str = if keep_alive { "keep-alive" } else { "close" };

        let header_str = format!(
            "HTTP/1.1 {} {}\r\n\
             Content-Type: application/text\r\n\
             Content-Length: {}\r\n\
             Connection: {}\r\n\
             Cache-Control: no-cache\r\n\
             Pragma: no-cache\r\n\
             \r\n",
            status_code,
            status_text,
            encrypted_body.len(),
            conn_str
        );

        let mut response_bytes = header_str.into_bytes();
        response_bytes.extend_from_slice(&encrypted_body);
        Ok(response_bytes)
    }

    /// Decodes an encrypted HTTP response received by the agent from the server.
    pub fn decode_agent_response(
        config: &DecoyTunnelConfig,
        raw_http: &[u8],
    ) -> Result<(DecoyHttpResponse, Vec<u8>), DecoyTunnelError> {
        let double_crlf = b"\r\n\r\n";
        let header_end = raw_http
            .windows(4)
            .position(|w| w == double_crlf)
            .ok_or(DecoyTunnelError::ShortBuffer)?;

        let header_slice = &raw_http[..header_end];
        let body_slice = &raw_http[header_end + 4..];

        let header_str = core::str::from_utf8(header_slice)
            .map_err(|_| DecoyTunnelError::InvalidHttpFormat)?;

        let mut lines = header_str.split("\r\n");
        let status_line = lines.next().ok_or(DecoyTunnelError::InvalidHttpFormat)?;
        let status_parts: Vec<&str> = status_line.split_whitespace().collect();
        if status_parts.len() < 2 {
            return Err(DecoyTunnelError::InvalidHttpFormat);
        }

        let version = status_parts[0].replace("HTTP/", "");
        let status_code = status_parts[1]
            .parse::<u16>()
            .map_err(|_| DecoyTunnelError::InvalidHttpFormat)?;
        let status_text = if status_parts.len() > 2 {
            status_parts[2..].join(" ")
        } else {
            "OK".to_string()
        };

        let mut content_length = 0usize;
        let mut keep_alive = true;
        let mut raw_headers = Vec::new();

        for line in lines {
            if line.is_empty() {
                continue;
            }
            if let Some(colon) = line.find(':') {
                let name = line[..colon].trim().to_ascii_lowercase();
                let val = line[colon + 1..].trim().to_string();

                match name.as_str() {
                    "content-length" => {
                        content_length = val.parse::<usize>().unwrap_or(0);
                    }
                    "connection" => {
                        keep_alive = val.to_ascii_lowercase().contains("keep-alive");
                    }
                    _ => {}
                }
                raw_headers.push((name, val));
            }
        }

        let actual_body = if body_slice.len() > content_length && content_length > 0 {
            &body_slice[..content_length]
        } else {
            body_slice
        };

        let key = config.derive_aes_key();
        let decrypted_body = if !actual_body.is_empty() {
            DecoyEnvelope::decrypt(actual_body, &key)?
        } else {
            Vec::new()
        };

        let parsed_resp = DecoyHttpResponse {
            version,
            status_code,
            status_text,
            content_length,
            keep_alive,
            raw_headers,
            raw_body: actual_body.to_vec(),
        };

        Ok((parsed_resp, decrypted_body))
    }
}

/// Tracks the lifecycle and telemetry of an individual decoy tunnel session.
#[derive(Debug, Clone)]
pub struct DecoyTunnelSession {
    pub session_id: String,
    pub is_connected: bool,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub active_action: DecoyAction,
}

impl DecoyTunnelSession {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            is_connected: false,
            bytes_sent: 0,
            bytes_received: 0,
            active_action: DecoyAction::Open,
        }
    }

    pub fn mark_connected(&mut self) {
        self.is_connected = true;
        self.active_action = DecoyAction::Send;
    }

    pub fn record_sent(&mut self, bytes: usize) {
        self.bytes_sent += bytes as u64;
    }

    pub fn record_received(&mut self, bytes: usize) {
        self.bytes_received += bytes as u64;
    }

    pub fn mark_closed(&mut self) {
        self.is_connected = false;
        self.active_action = DecoyAction::Close;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_cbc_envelope_roundtrip() {
        let key = [0x42u8; 32];
        let message = b"GET /index.html HTTP/1.1\r\nHost: example.org\r\n\r\n";

        let encrypted = DecoyEnvelope::encrypt(message, &key).expect("Encryption failed");
        assert!(encrypted.len() >= 16 + message.len());

        let decrypted = DecoyEnvelope::decrypt(&encrypted, &key).expect("Decryption failed");
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_hex_codec_roundtrip() {
        let original = b"\x00\x01\x02\xfe\xffHelloDecoyWorld";
        let hex = DecoyEnvelope::encode_hex(original);
        assert_eq!(hex.len(), original.len() * 2);

        let recovered = DecoyEnvelope::decode_hex(&hex).expect("Hex decoding failed");
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_agent_request_codec_roundtrip() {
        let config = DecoyTunnelConfig::default();
        let session_id = "test-session-uuid-1234";
        let payload = b"CONNECT target.server.internal:443 HTTP/1.1\r\nHost: target.server.internal\r\n\r\n";

        let wire_request = DecoyHttpCodec::encode_agent_request(
            &config,
            session_id,
            DecoyAction::Open,
            payload,
            0,
        )
        .expect("Agent request encoding failed");

        let (parsed_req, decoded_payload) =
            DecoyHttpCodec::decode_server_request(&config, &wire_request)
                .expect("Server request decoding failed");

        assert_eq!(parsed_req.session_id, session_id);
        assert_eq!(parsed_req.action, DecoyAction::Open);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_server_response_codec_roundtrip() {
        let config = DecoyTunnelConfig::default();
        let payload = b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: LumiNet\r\n\r\n";

        let wire_response = DecoyHttpCodec::encode_server_response(
            &config,
            200,
            "Connection Established",
            payload,
            true,
        )
        .expect("Server response encoding failed");

        let (parsed_resp, decoded_payload) =
            DecoyHttpCodec::decode_agent_response(&config, &wire_response)
                .expect("Agent response decoding failed");

        assert_eq!(parsed_resp.status_code, 200);
        assert!(parsed_resp.keep_alive);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_invalid_key_decryption_failure() {
        let key_correct = [0x55u8; 32];
        let key_wrong = [0xaau8; 32];
        let secret = b"super-confidential-proxy-stream";

        let encrypted = DecoyEnvelope::encrypt(secret, &key_correct).unwrap();
        let res = DecoyEnvelope::decrypt(&encrypted, &key_wrong);
        assert!(res.is_err());
    }

    #[test]
    fn test_action_parsing() {
        assert_eq!("open".parse::<DecoyAction>().unwrap(), DecoyAction::Open);
        assert_eq!("request".parse::<DecoyAction>().unwrap(), DecoyAction::Request);
        assert_eq!("send".parse::<DecoyAction>().unwrap(), DecoyAction::Send);
        assert_eq!("recv".parse::<DecoyAction>().unwrap(), DecoyAction::Recv);
        assert_eq!("close".parse::<DecoyAction>().unwrap(), DecoyAction::Close);
        assert_eq!(
            "custom-action".parse::<DecoyAction>().unwrap(),
            DecoyAction::Custom("custom-action".to_string())
        );
    }

    #[test]
    fn test_session_lifecycle() {
        let mut session = DecoyTunnelSession::new("sess-1");
        assert!(!session.is_connected);

        session.mark_connected();
        assert!(session.is_connected);
        assert_eq!(session.active_action, DecoyAction::Send);

        session.record_sent(1024);
        session.record_received(4096);
        assert_eq!(session.bytes_sent, 1024);
        assert_eq!(session.bytes_received, 4096);

        session.mark_closed();
        assert!(!session.is_connected);
        assert_eq!(session.active_action, DecoyAction::Close);
    }
}
