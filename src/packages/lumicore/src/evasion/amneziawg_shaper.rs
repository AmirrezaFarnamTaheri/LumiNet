// SPDX-License-Identifier: MIT
// AmneziaWG 3.1 Obfuscation Engine & Parameter Validator
// Enforces kernel DKMS & amneziawg-go UAPI constraints:
// - Jc (junk packet count), Jmin/Jmax (junk packet size range)
// - S1/S2 (handshake padding where S1+56 != S2), S3 (cookie padding), S4 (transport padding)
// - H1..H4 (header type range mapping in [5, 2147483647])
// - I1..I5 (CPS signature packet slots)
// - Header protection key (32 bytes) with S1..S4 >= 12 requirement

use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const AWG_H_MAX: u32 = 2147483647; // 2^31 - 1
pub const H_MIN_WIDTH: u32 = 1000;
pub const MAX_FORWARDED_PORTS: usize = 100;

/// AmneziaWG 3.1 obfuscation parameter set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Obfuscation31 {
    pub jc: u32,
    pub jmin: u32,
    pub jmax: u32,
    pub s1: u32,
    pub s2: u32,
    pub s3: u32,
    pub s4: u32,
    pub h1: String,
    pub h2: String,
    pub h3: String,
    pub h4: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i2: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i3: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i5: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_protection_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_padding_addition: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rekey_after_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rekey_timeout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reject_after_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keepalive_timeout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_handshake_attempts: Option<String>,
    pub random_trailers: bool,
    pub disable_cookies: bool,
}

impl Default for Obfuscation31 {
    fn default() -> Self {
        Self::generate()
    }
}

impl Obfuscation31 {
    /// Generates a randomized AmneziaWG 3.1 parameter set adhering to all kernel constraints.
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();

        let jc = rng.gen_range(3..=6);
        let jmin = rng.gen_range(40..=89);
        let jmax = jmin + rng.gen_range(50..=250);

        let s1 = rng.gen_range(15..=150);
        let mut s2 = rng.gen_range(15..=150);
        // Kernel constraint: S1+56 != S2, else init and response handshake packets end up the same size
        while s1 + 56 == s2 {
            s2 = rng.gen_range(15..=150);
        }

        // Floored at 12: HeaderProtectionKey requires S1-S4 >= 12
        let s3 = rng.gen_range(12..=55);
        let s4 = rng.gen_range(12..=27);

        let h_ranges = generate_h_ranges(&mut rng);

        // CPS signature packet: <r N> random bytes before handshake
        let i1 = Some(format!("<r {}>", rng.gen_range(32..=256)));

        // Generate 32-byte header protection key
        let mut hp_key = [0u8; 32];
        rng.fill(&mut hp_key);
        let header_protection_key = Some(base64_encode(&hp_key));

        let cp_lo = rng.gen_range(8..=24);
        let content_padding_addition = Some(format!("{}-{}", cp_lo, cp_lo + rng.gen_range(8..=40)));

        let rk_lo = rng.gen_range(100..=120);
        let rk_hi = rk_lo + rng.gen_range(10..=40);
        let rekey_after_time = Some(format!("{}-{}", rk_lo, rk_hi));

        let rj_lo = rk_hi + rng.gen_range(30..=60);
        let reject_after_time = Some(format!("{}-{}", rj_lo, rj_lo + rng.gen_range(30..=90)));

        let rt_lo = rng.gen_range(3..=6);
        let rekey_timeout = Some(format!("{}-{}", rt_lo, rt_lo + rng.gen_range(1..=4)));

        let ka_lo = rng.gen_range(8..=12);
        let keepalive_timeout = Some(format!("{}-{}", ka_lo, ka_lo + rng.gen_range(2..=8)));

        let ha_lo = rng.gen_range(15..=25);
        let max_handshake_attempts = Some(format!("{}-{}", ha_lo, ha_lo + rng.gen_range(5..=25)));

        Self {
            jc,
            jmin,
            jmax,
            s1,
            s2,
            s3,
            s4,
            h1: h_ranges[0].clone(),
            h2: h_ranges[1].clone(),
            h3: h_ranges[2].clone(),
            h4: h_ranges[3].clone(),
            i1,
            i2: None,
            i3: None,
            i4: None,
            i5: None,
            header_protection_key,
            content_padding_addition,
            rekey_after_time,
            rekey_timeout,
            reject_after_time,
            keepalive_timeout,
            max_handshake_attempts,
            random_trailers: true,
            disable_cookies: true,
        }
    }

    /// Validates obfuscation parameters against AmneziaWG protocol invariants.
    pub fn validate(&self) -> Result<(), AmneziaValidationError> {
        if self.jmin > self.jmax {
            return Err(AmneziaValidationError(format!(
                "invalid Jmin/Jmax: {} must not exceed {}",
                self.jmin, self.jmax
            )));
        }
        if self.s3 > 64 {
            return Err(AmneziaValidationError(format!(
                "invalid S3 value {} (must be 0..64)",
                self.s3
            )));
        }
        if self.s4 > 32 {
            return Err(AmneziaValidationError(format!(
                "invalid S4 value {} (must be 0..32)",
                self.s4
            )));
        }
        if self.s1 + 56 == self.s2 {
            return Err(AmneziaValidationError(format!(
                "invalid S1/S2: S1+56 must not equal S2 ({} + 56 == {})",
                self.s1, self.s2
            )));
        }

        // Validate H ranges
        for (idx, h) in [&self.h1, &self.h2, &self.h3, &self.h4].iter().enumerate() {
            validate_uint_range(h, 0).map_err(|e| {
                AmneziaValidationError(format!("invalid H{}: {}", idx + 1, e.0))
            })?;
        }

        // Validate header protection key and minimum S1-S4 >= 12
        if let Some(ref hp_key) = self.header_protection_key {
            let decoded = base64_decode(hp_key)
                .map_err(|_| AmneziaValidationError("headerProtectionKey is not valid base64".into()))?;
            if decoded.len() != 32 {
                return Err(AmneziaValidationError(format!(
                    "headerProtectionKey must be 32 bytes, got {}",
                    decoded.len()
                )));
            }
            for (idx, s) in [self.s1, self.s2, self.s3, self.s4].iter().enumerate() {
                if *s < 12 {
                    return Err(AmneziaValidationError(format!(
                        "invalid S{} value {}: header protection requires S1-S4 >= 12",
                        idx + 1,
                        s
                    )));
                }
            }
        }

        // Validate timing windows (Rekey must fire before Reject)
        if let (Some(ref rk), Some(ref rj)) = (&self.rekey_after_time, &self.reject_after_time) {
            let (_, rk_hi) = parse_uint_range(rk).map_err(|e| AmneziaValidationError(e.0))?;
            let (rj_lo, _) = parse_uint_range(rj).map_err(|e| AmneziaValidationError(e.0))?;
            if rk_hi >= rj_lo {
                return Err(AmneziaValidationError(format!(
                    "invalid rekey/reject timing: max rekey {} must be strictly below min reject {}",
                    rk_hi, rj_lo
                )));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmneziaValidationError(pub String);

impl fmt::Display for AmneziaValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for AmneziaValidationError {}

fn generate_h_ranges<R: Rng>(rng: &mut R) -> [String; 4] {
    const LO: u32 = 5;
    let band_size = (AWG_H_MAX - LO + 1) / 4;
    let mut out = [String::new(), String::new(), String::new(), String::new()];

    for i in 0..4 {
        let band_lo = LO + i as u32 * band_size;
        let band_hi = band_lo + band_size - 1;
        let start = rng.gen_range(band_lo..=(band_hi - H_MIN_WIDTH - 1));
        let end = rng.gen_range((start + H_MIN_WIDTH)..=band_hi);
        out[i] = format!("{}-{}", start, end);
    }
    out
}

fn parse_uint_range(v: &str) -> Result<(u32, u32), AmneziaValidationError> {
    let clean = v.trim().replace(' ', "");
    if let Some((start_s, end_s)) = clean.split_once('-') {
        let start: u32 = start_s
            .parse()
            .map_err(|_| AmneziaValidationError(format!("invalid range start: {}", start_s)))?;
        let end: u32 = end_s
            .parse()
            .map_err(|_| AmneziaValidationError(format!("invalid range end: {}", end_s)))?;
        if start > end {
            return Err(AmneziaValidationError(format!(
                "range start {} exceeds end {}",
                start, end
            )));
        }
        Ok((start, end))
    } else {
        let single: u32 = clean
            .parse()
            .map_err(|_| AmneziaValidationError(format!("invalid integer: {}", clean)))?;
        Ok((single, single))
    }
}

fn validate_uint_range(v: &str, min_val: u32) -> Result<(), AmneziaValidationError> {
    let clean = v.trim().replace(' ', "");
    if clean.is_empty() {
        return Ok(());
    }
    let (start, _) = parse_uint_range(&clean)?;
    if start < min_val {
        return Err(AmneziaValidationError(format!(
            "value {} is below minimum required {}",
            start, min_val
        )));
    }
    Ok(())
}

/// Port forwarding range specifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortSpec {
    pub start: u16,
    pub end: u16,
}

/// Parses a user-supplied port forwarding string ("80, 443; 8000-8100") into unique, sorted ports,
/// capped at MAX_FORWARDED_PORTS (100) to prevent descriptor exhaustion.
pub fn parse_forwarded_ports(input: &str) -> Vec<u16> {
    if input.is_empty() {
        return Vec::new();
    }
    let normalized = input.replace(';', ",");
    let mut ports = Vec::new();

    for tok in normalized.split(',') {
        let t = tok.trim();
        if t.is_empty() {
            continue;
        }
        if let Some((s_str, e_str)) = t.split_once('-') {
            if let (Ok(s), Ok(e)) = (s_str.trim().parse::<u16>(), e_str.trim().parse::<u16>()) {
                if s <= e && s >= 1 {
                    for p in s..=e {
                        if !ports.contains(&p) {
                            ports.push(p);
                            if ports.len() >= MAX_FORWARDED_PORTS {
                                ports.sort_unstable();
                                return ports;
                            }
                        }
                    }
                }
            }
        } else if let Ok(p) = t.parse::<u16>() {
            if p >= 1 && !ports.contains(&p) {
                ports.push(p);
                if ports.len() >= MAX_FORWARDED_PORTS {
                    ports.sort_unstable();
                    return ports;
                }
            }
        }
    }

    ports.sort_unstable();
    ports
}

/// Checks if a port is contained in the user-supplied forwarded ports string.
pub fn forwarded_ports_include(input: &str, port: u16) -> bool {
    parse_forwarded_ports(input).contains(&port)
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i];
        let b1 = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
        let b2 = if i + 2 < bytes.len() { bytes[i + 2] } else { 0 };

        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);

        if i + 1 < bytes.len() {
            out.push(ALPHABET[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }

        if i + 2 < bytes.len() {
            out.push(ALPHABET[(b2 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }

        i += 3;
    }
    out
}

fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    let clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = clean.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err(());
    }

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut val: u32 = 0;
        let mut pad = 0;
        for (i, &b) in chunk.iter().enumerate() {
            let v = match b {
                b'A'..=b'Z' => (b - b'A') as u32,
                b'a'..=b'z' => (b - b'a' + 26) as u32,
                b'0'..=b'9' => (b - b'0' + 52) as u32,
                b'+' => 62,
                b'/' => 63,
                b'=' => {
                    pad += 1;
                    0
                }
                _ => return Err(()),
            };
            val = (val << 6) | v;
            if pad > 0 && i >= 2 && b != b'=' {
                return Err(());
            }
        }
        out.push((val >> 16) as u8);
        if pad < 2 {
            out.push((val >> 8) as u8);
        }
        if pad < 1 {
            out.push(val as u8);
        }
    }
    Ok(out)
}
