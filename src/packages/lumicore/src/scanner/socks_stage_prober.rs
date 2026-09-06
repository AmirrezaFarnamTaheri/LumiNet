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

//! # SOCKS Active Prober & Connection Stage Ladder
//!
//! Provides active SOCKS5 handshake probing, Cloudflare edge trace validation (`/cdn-cgi/trace`),
//! multi-stage attempt ladder budgeting, and connection phase transitions.
//! Ported and unified from `oblivion-main` (`probe.rs` & `supervisor.rs`).

use std::fmt;
use std::string::String;
use std::string::ToString;
use std::vec::Vec;

/// SOCKS5 probe target parameters.
#[derive(Debug, Clone)]
pub struct SocksProbeConfig {
    pub probe_host: String,
    pub probe_port: u16,
    pub probe_path: String,
    pub connect_timeout_ms: u64,
    pub io_timeout_ms: u64,
}

impl Default for SocksProbeConfig {
    fn default() -> Self {
        Self {
            probe_host: "connectivity.cloudflareclient.com".to_string(),
            probe_port: 80,
            probe_path: "/cdn-cgi/trace".to_string(),
            connect_timeout_ms: 4000,
            io_timeout_ms: 4000,
        }
    }
}

/// Parsed metadata from a `/cdn-cgi/trace` response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CloudflareTraceResult {
    pub fl: Option<String>,
    pub h: Option<String>,
    pub ip: Option<String>,
    pub ts: Option<String>,
    pub visit_scheme: Option<String>,
    pub uag: Option<String>,
    pub colo: Option<String>,
    pub sliver: Option<String>,
    pub http: Option<String>,
    pub loc: Option<String>,
    pub tls: Option<String>,
    pub sni: Option<String>,
    pub warp: Option<String>,
    pub is_warp_ok: bool,
    pub raw: String,
}

/// Packet builder and verifier for SOCKS5 RFC 1928 negotiations.
pub struct SocksPacketBuilder;

impl SocksPacketBuilder {
    /// Returns the initial SOCKS5 client greeting packet (no authentication).
    pub fn build_greeting() -> [u8; 3] {
        [0x05, 0x01, 0x00]
    }

    /// Verifies server response to initial greeting.
    pub fn verify_greeting(reply: &[u8]) -> bool {
        reply.len() >= 2 && reply[0] == 0x05 && reply[1] == 0x00
    }

    /// Builds a SOCKS5 CONNECT command targeting a domain name.
    pub fn build_connect_request(host: &str, port: u16) -> Vec<u8> {
        let host_bytes = host.as_bytes();
        let mut request = Vec::with_capacity(7 + host_bytes.len());
        // VER 5, CMD 1 (CONNECT), RSV 0, ATYP 3 (Domain), LEN
        request.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8]);
        request.extend_from_slice(host_bytes);
        request.extend_from_slice(&port.to_be_bytes());
        request
    }

    /// Verifies server CONNECT reply header (first 4 bytes).
    /// Returns the number of trailing bound address bytes to discard if successful.
    pub fn verify_connect_reply(head: &[u8]) -> Result<usize, &'static str> {
        if head.len() < 4 {
            return Err("Incomplete connect reply");
        }
        if head[0] != 0x05 {
            return Err("Invalid SOCKS version");
        }
        if head[1] != 0x00 {
            return Err("SOCKS connect rejected by server");
        }

        match head[3] {
            0x01 => Ok(4 + 2),  // IPv4: 4 bytes IP + 2 bytes port
            0x04 => Ok(16 + 2), // IPv6: 16 bytes IP + 2 bytes port
            0x03 => Ok(1),      // Domain: 1 byte len prefix, then dynamic
            _ => Err("Unsupported ATYP in SOCKS reply"),
        }
    }

    /// Formats an HTTP/1.1 probe request string targeting the probe path.
    pub fn build_http_probe_request(host: &str, path: &str, user_agent: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\nConnection: close\r\n\r\n")
    }

    /// Parses the raw body of `/cdn-cgi/trace` into structured metadata.
    pub fn parse_trace_body(body: &str) -> CloudflareTraceResult {
        let mut res = CloudflareTraceResult {
            raw: body.to_string(),
            ..Default::default()
        };

        for line in body.lines() {
            if let Some((k, v)) = line.split_once('=') {
                let key = k.trim();
                let val = v.trim().to_string();
                match key {
                    "fl" => res.fl = Some(val),
                    "h" => res.h = Some(val),
                    "ip" => res.ip = Some(val),
                    "ts" => res.ts = Some(val),
                    "visit_scheme" => res.visit_scheme = Some(val),
                    "uag" => res.uag = Some(val),
                    "colo" => res.colo = Some(val),
                    "sliver" => res.sliver = Some(val),
                    "http" => res.http = Some(val),
                    "loc" => res.loc = Some(val),
                    "tls" => res.tls = Some(val),
                    "sni" => res.sni = Some(val),
                    "warp" => {
                        res.is_warp_ok = val == "on" || val == "plus";
                        res.warp = Some(val);
                    }
                    _ => {}
                }
            }
        }

        res
    }
}

/// Lifecycle phases of an active connection attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptPhase {
    Initializing,
    StartingHelper,
    ScanningEndpoints,
    AwaitingSocks,
    ValidatingConnectivity,
    Engaged,
    Recovering,
    Failed,
}

impl AttemptPhase {
    pub fn as_str(&self) -> &str {
        match self {
            AttemptPhase::Initializing => "Initializing",
            AttemptPhase::StartingHelper => "StartingHelper",
            AttemptPhase::ScanningEndpoints => "ScanningEndpoints",
            AttemptPhase::AwaitingSocks => "AwaitingSocks",
            AttemptPhase::ValidatingConnectivity => "ValidatingConnectivity",
            AttemptPhase::Engaged => "Engaged",
            AttemptPhase::Recovering => "Recovering",
            AttemptPhase::Failed => "Failed",
        }
    }
}

impl fmt::Display for AttemptPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Definition of an individual attempt within the connection strategy ladder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptStage {
    pub label: String,
    pub noize: String,
    pub scan: String,
    pub budget_sec: u64,
}

/// Connection attempt ladder calculator .rs`.
pub struct AttemptLadder;

impl AttemptLadder {
    pub const POST_SCAN_HEADROOM_SEC: u64 = 60;
    pub const FAST_ATTEMPT_BUDGET_SEC: u64 = 30;

    /// Computes timeout budget in seconds for a given scan mode.
    pub fn calculate_validation_budget(scan_mode: &str) -> u64 {
        let scan_budget = match scan_mode.trim().to_ascii_lowercase().as_str() {
            "turbo" | "fast" => 45,
            "thorough" | "deep" | "pro" => 300,
            "stealth" | "quiet" => 180,
            "ironclad" | "real" | "verify" | "guaranteed" => 180,
            _ => 120,
        };
        scan_budget + Self::POST_SCAN_HEADROOM_SEC
    }

    /// Builds the ordered sequence of attempts (Fast first connect fallback ladder).
    pub fn build_attempts(
        scan_mode: &str,
        noize_profile: &str,
        fast_first_connect: bool,
        uses_psiphon: bool,
    ) -> Vec<AttemptStage> {
        let configured = AttemptStage {
            label: "configured".to_string(),
            noize: noize_profile.to_string(),
            scan: scan_mode.to_string(),
            budget_sec: Self::calculate_validation_budget(scan_mode),
        };

        if uses_psiphon || !fast_first_connect {
            return vec![configured];
        }

        let fast = AttemptStage {
            label: "fast".to_string(),
            noize: "off".to_string(),
            scan: "turbo".to_string(),
            budget_sec: Self::FAST_ATTEMPT_BUDGET_SEC,
        };

        if fast.noize == configured.noize && fast.scan == configured.scan {
            return vec![configured];
        }

        vec![fast, configured]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks_greeting_and_connect_builder() {
        let greeting = SocksPacketBuilder::build_greeting();
        assert_eq!(greeting, [0x05, 0x01, 0x00]);
        assert!(SocksPacketBuilder::verify_greeting(&[0x05, 0x00]));
        assert!(!SocksPacketBuilder::verify_greeting(&[0x05, 0xff]));

        let req = SocksPacketBuilder::build_connect_request("example.com", 443);
        assert_eq!(req[0], 0x05); // VER
        assert_eq!(req[1], 0x01); // CMD = CONNECT
        assert_eq!(req[2], 0x00); // RSV
        assert_eq!(req[3], 0x03); // ATYP = Domain
        assert_eq!(req[4], 11);   // Length of "example.com"
        assert_eq!(&req[5..16], b"example.com");
        assert_eq!(&req[16..18], &443u16.to_be_bytes());
    }

    #[test]
    fn test_verify_connect_reply() {
        // Successful IPv4 connect reply: [0x05, 0x00, 0x00, 0x01]
        let reply_ipv4 = [0x05, 0x00, 0x00, 0x01];
        assert_eq!(SocksPacketBuilder::verify_connect_reply(&reply_ipv4).unwrap(), 6);

        // Server error reply: [0x05, 0x01, 0x00, 0x01]
        let reply_err = [0x05, 0x01, 0x00, 0x01];
        assert!(SocksPacketBuilder::verify_connect_reply(&reply_err).is_err());
    }

    #[test]
    fn test_parse_trace_body() {
        let body = "fl=42f10\nh=connectivity.cloudflareclient.com\nip=1.2.3.4\nts=1713988096\nvisit_scheme=http\nuag=Oblivion\ncolo=FRA\nsliver=none\nhttp=http/1.1\nloc=DE\ntls=off\nsni=plaintext\nwarp=on\n";
        let parsed = SocksPacketBuilder::parse_trace_body(body);

        assert_eq!(parsed.colo.as_deref(), Some("FRA"));
        assert_eq!(parsed.loc.as_deref(), Some("DE"));
        assert_eq!(parsed.ip.as_deref(), Some("1.2.3.4"));
        assert_eq!(parsed.warp.as_deref(), Some("on"));
        assert!(parsed.is_warp_ok);
    }

    #[test]
    fn test_attempt_ladder_budgeting() {
        assert_eq!(AttemptLadder::calculate_validation_budget("turbo"), 105);
        assert_eq!(AttemptLadder::calculate_validation_budget("thorough"), 360);
        assert_eq!(AttemptLadder::calculate_validation_budget("stealth"), 240);
        assert_eq!(AttemptLadder::calculate_validation_budget("standard"), 180);
    }

    #[test]
    fn test_attempt_ladder_stages() {
        // Fast first connect enabled with standard config -> 2 attempts
        let ladder = AttemptLadder::build_attempts("standard", "m1", true, false);
        assert_eq!(ladder.len(), 2);
        assert_eq!(ladder[0].label, "fast");
        assert_eq!(ladder[0].budget_sec, 30);
        assert_eq!(ladder[1].label, "configured");
        assert_eq!(ladder[1].budget_sec, 180);

        // Psiphon mode -> single configured attempt
        let psiphon_ladder = AttemptLadder::build_attempts("standard", "m1", true, true);
        assert_eq!(psiphon_ladder.len(), 1);
        assert_eq!(psiphon_ladder[0].label, "configured");
    }
}
