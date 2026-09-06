//! # Noise Packet Shaper & Custom Packet Sequence (CPS) Generator
//!
//! Provides WireGuard / UDP anti-censorship packet obfuscation through
//! randomized junk packet bursts and custom initiation sequence tags.
//! Ported and elevated from Aether's CPS (Custom Packet Sequence) specification.

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use rand::{Rng, RngCore};
use regex::Regex;

/// Predefined profiles for transport noise injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoizeProfile {
    Off,
    Light,
    Balanced,
    Aggressive,
}

/// Configuration for noise packet shaping and handshake delay.
#[derive(Debug, Clone)]
pub struct NoizeConfig {
    pub profile: NoizeProfile,
    pub i1: Option<String>,
    pub i2: Option<String>,
    pub i3: Option<String>,
    pub i4: Option<String>,
    pub i5: Option<String>,
    pub junk_count: usize,
    pub junk_before_hs: usize,
    pub junk_after_i1: usize,
    pub junk_after_hs: usize,
    pub junk_min_size: usize,
    pub junk_max_size: usize,
    pub junk_interval: Duration,
    pub handshake_delay: Duration,
    pub allow_zero_size: bool,
}

impl NoizeConfig {
    /// Disabled noise shaper (zero overhead).
    pub fn off() -> Self {
        Self {
            profile: NoizeProfile::Off,
            i1: None,
            i2: None,
            i3: None,
            i4: None,
            i5: None,
            junk_count: 0,
            junk_before_hs: 0,
            junk_after_i1: 0,
            junk_after_hs: 0,
            junk_min_size: 0,
            junk_max_size: 0,
            junk_interval: Duration::ZERO,
            handshake_delay: Duration::ZERO,
            allow_zero_size: false,
        }
    }

    /// Light noise injection suitable for mobile or low-bandwidth links.
    pub fn light() -> Self {
        Self {
            profile: NoizeProfile::Light,
            i1: Some("<b 0d0a0d0a><t><r 20-32>".to_string()),
            i2: Some("<rc 24-48>".to_string()),
            i3: None,
            i4: None,
            i5: None,
            junk_count: 4,
            junk_before_hs: 2,
            junk_after_i1: 1,
            junk_after_hs: 1,
            junk_min_size: 48,
            junk_max_size: 190,
            junk_interval: Duration::from_millis(3),
            handshake_delay: Duration::from_millis(5),
            allow_zero_size: false,
        }
    }

    /// Balanced profile providing reliable DPI confusion for stateful middleboxes.
    pub fn balanced() -> Self {
        Self {
            profile: NoizeProfile::Balanced,
            i1: Some("<b 0d0a0d0a><t><rc 20-40>".to_string()),
            i2: Some("<b 504f5354><rd 10-20><rc 20-30>".to_string()),
            i3: Some("<r 30-50>".to_string()),
            i4: None,
            i5: None,
            junk_count: 6,
            junk_before_hs: 3,
            junk_after_i1: 2,
            junk_after_hs: 1,
            junk_min_size: 64,
            junk_max_size: 256,
            junk_interval: Duration::from_millis(2),
            handshake_delay: Duration::from_millis(8),
            allow_zero_size: false,
        }
    }

    /// Aggressive profile designed to defeat strict protocol white-listing.
    pub fn aggressive() -> Self {
        Self {
            profile: NoizeProfile::Aggressive,
            i1: Some("<b 0d0a0d0a><t><rc 40-64>".to_string()),
            i2: Some("<b 504f5354><t><rd 15-30><rc 30-50>".to_string()),
            i3: Some("<b 474554><rc 40-60>".to_string()),
            i4: Some("<r 60-100>".to_string()),
            i5: Some("<c><rd 20-40>".to_string()),
            junk_count: 10,
            junk_before_hs: 4,
            junk_after_i1: 3,
            junk_after_hs: 3,
            junk_min_size: 80,
            junk_max_size: 384,
            junk_interval: Duration::from_millis(1),
            handshake_delay: Duration::from_millis(12),
            allow_zero_size: false,
        }
    }

    /// Factory constructor from profile enum.
    pub fn from_profile(profile: NoizeProfile) -> Self {
        match profile {
            NoizeProfile::Off => Self::off(),
            NoizeProfile::Light => Self::light(),
            NoizeProfile::Balanced => Self::balanced(),
            NoizeProfile::Aggressive => Self::aggressive(),
        }
    }

    /// Returns true if noise shaping or custom handshake sequences are active.
    pub fn is_enabled(&self) -> bool {
        self.junk_count > 0 || self.i1.is_some()
    }

    /// Generates the configured junk packet payload burst.
    pub fn generate_junk_packets(&self) -> Vec<Vec<u8>> {
        if self.junk_count == 0 || self.junk_max_size == 0 {
            return Vec::new();
        }
        let mut rng = rand::thread_rng();
        let mut packets = Vec::with_capacity(self.junk_count);
        for _ in 0..self.junk_count {
            let len = if self.junk_max_size > self.junk_min_size {
                rng.gen_range(self.junk_min_size..=self.junk_max_size)
            } else {
                self.junk_min_size
            };
            let mut payload = vec![0u8; len];
            rng.fill_bytes(&mut payload);
            packets.push(payload);
        }
        packets
    }
}

/// Parses a min-max range string such as `"20-30"` or a fixed number `"42"`.
fn parse_range(data: &str) -> usize {
    let mut parts = data.split('-');
    if let (Some(min_str), Some(max_str)) = (parts.next(), parts.next()) {
        let min: usize = min_str.trim().parse().unwrap_or(0);
        let max: usize = max_str.trim().parse().unwrap_or(0);
        if max >= min && min > 0 {
            return rand::thread_rng().gen_range(min..=max).min(2048);
        }
    }
    data.trim().parse().unwrap_or(0).min(2048)
}

/// Parses a Custom Packet Sequence (CPS) specification into concrete bytes.
///
/// Supported tags:
/// - `<b hex>`: Exact hexadecimal byte literals.
/// - `<t>`: Current 4-byte UNIX timestamp in big-endian order.
/// - `<c>`: 4-byte counter/second timestamp.
/// - `<r min-max>`: Cryptographically random raw bytes within range.
/// - `<rc min-max>`: Random ASCII alphabetic characters `[a-zA-Z]`.
/// - `<rd min-max>`: Random ASCII decimal digits `[0-9]`.
/// Decodes a hexadecimal string into a byte vector.
fn decode_hex(hex_str: &str) -> Option<Vec<u8>> {
    let clean = hex_str
        .strip_prefix("0x")
        .or_else(|| hex_str.strip_prefix("0X"))
        .unwrap_or(hex_str);
    if clean.len() % 2 != 0 {
        return None;
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).ok())
        .collect()
}

pub fn parse_cps(spec: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let tag_regex = Regex::new(r"<([a-z]+)\s*([^>]*)>").unwrap();

    for cap in tag_regex.captures_iter(spec) {
        let tag_type = cap.get(1).map_or("", |m| m.as_str());
        let tag_data = cap.get(2).map_or("", |m| m.as_str()).trim();

        match tag_type {
            "b" => {
                let hex_str: String = tag_data.chars().filter(|c| !c.is_whitespace()).collect();
                if let Some(decoded) = decode_hex(&hex_str) {
                    out.extend_from_slice(&decoded);
                }
            }
            "t" => {
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(0);
                out.extend_from_slice(&ts.to_be_bytes());
            }
            "c" => {
                let counter = (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
                    % 0xFFFFFFFF) as u32;
                out.extend_from_slice(&counter.to_be_bytes());
            }
            "r" => {
                let len = parse_range(tag_data);
                if len > 0 {
                    let mut r = vec![0u8; len];
                    rand::thread_rng().fill_bytes(&mut r);
                    out.extend_from_slice(&r);
                }
            }
            "rc" => {
                let len = parse_range(tag_data);
                if len > 0 {
                    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
                    let mut r = vec![0u8; len];
                    let mut rng = rand::thread_rng();
                    for b in r.iter_mut() {
                        *b = CHARS[rng.gen_range(0..CHARS.len())];
                    }
                    out.extend_from_slice(&r);
                }
            }
            "rd" => {
                let len = parse_range(tag_data);
                if len > 0 {
                    const DIGITS: &[u8] = b"0123456789";
                    let mut r = vec![0u8; len];
                    let mut rng = rand::thread_rng();
                    for b in r.iter_mut() {
                        *b = DIGITS[rng.gen_range(0..DIGITS.len())];
                    }
                    out.extend_from_slice(&r);
                }
            }
            _ => {}
        }
    }

    out
}

/// Wraps a payload inside an authentic IKEv2 Security Association (SA) INIT header.
/// Disguises UDP transport traffic as legitimate IPsec IKEv2 negotiation packets.
pub fn wrap_ikev2(payload: &[u8]) -> Vec<u8> {
    if payload.is_empty() {
        return Vec::new();
    }

    let mut initiator_spi = [0u8; 8];
    let mut responder_spi = [0u8; 8];

    if payload.len() >= 8 {
        initiator_spi.copy_from_slice(&payload[..8]);
    } else {
        rand::thread_rng().fill_bytes(&mut initiator_spi);
    }
    rand::thread_rng().fill_bytes(&mut responder_spi);

    let total_length = 28u32 + 24 + payload.len() as u32;
    let sa_payload_length = 24u16 + payload.len() as u16;

    let mut header = Vec::with_capacity(total_length as usize);

    header.extend_from_slice(&initiator_spi);
    header.extend_from_slice(&responder_spi);
    header.push(0x21); // Next payload: Security Association (SA)
    header.push(0x20); // Version: IKEv2 (2.0)
    header.push(0x22); // Exchange type: IKE_SA_INIT
    header.push(0x08); // Flags: Initiator
    header.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Message ID
    header.extend_from_slice(&total_length.to_be_bytes());

    header.push(0x00); // Next payload: None
    header.push(0x00); // Critical bit: 0
    header.extend_from_slice(&sa_payload_length.to_be_bytes());

    // Proposal 1, Protocol ID 1 (IKE), SPI size 0, 4 transforms
    header.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x14, 0x01, 0x01, 0x00, 0x04, 0x03, 0x00, 0x00, 0x08, 0x01, 0x00,
        0x00, 0x0c, 0x00, 0x00, 0x00, 0x00,
    ]);

    header.extend_from_slice(payload);
    header
}

/// Masks WireGuard message type byte if in range 1..=4 to avoid DPI heuristic fingerprinting.
pub fn mask_wireguard_header(byte: u8) -> u8 {
    if (1..=4).contains(&byte) {
        byte.wrapping_add(0x40)
    } else {
        byte
    }
}

