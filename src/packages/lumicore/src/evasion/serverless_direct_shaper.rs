//! # Serverless Direct Shaper & Zero-VPS Evasion Engine
//!
//! Implements direct-to-destination client-side packet shaping for bypassing deep packet
//! inspection without requiring a remote VPS proxy server.
//!

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Delay profiles for direct zero-VPS evasion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerlessProfile {
    /// Low delay mode: 1ms micro-delays between segments for real-time responsiveness.
    LowDelay,
    /// High delay mode: Rhythmic periodic delay bursts (e.g. 400ms stalls) to desync stateful DPI timers.
    HighDelay,
}

/// Fragment slice representation with transmission delay hint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShaperFragment {
    pub payload: Vec<u8>,
    pub delay_ms: u64,
}

/// Configuration for the serverless direct evasion shaper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerlessShaperConfig {
    pub profile: ServerlessProfile,
    pub tls_record_split: usize,
    pub sni_split_offset: usize,
    pub max_split_tls: usize,
    pub max_split_tcp: usize,
    pub happy_eyeballs_ipv6_first: bool,
    pub udp_noise_enabled: bool,
    pub udp_noise_min_len: usize,
    pub udp_noise_max_len: usize,
    pub udp_noise_reset_interval: u32,
}

impl Default for ServerlessShaperConfig {
    fn default() -> Self {
        Self {
            profile: ServerlessProfile::LowDelay,
            tls_record_split: 5,
            sni_split_offset: 43,
            max_split_tls: 522,
            max_split_tcp: 419,
            happy_eyeballs_ipv6_first: true,
            udp_noise_enabled: true,
            udp_noise_min_len: 1200,
            udp_noise_max_len: 1230,
            udp_noise_reset_interval: 28,
        }
    }
}

/// Engine for direct client-side traffic shaping.
pub struct ServerlessDirectShaper;

impl ServerlessDirectShaper {
    /// Checks if a destination IP matches known censorship redirection sinks.
    ///
    /// Iranian national censorship redirection page:
    /// - IPv4: 10.10.34.0/24
    /// - IPv6: 2001:4188:2:600::/64
    pub fn is_censorship_sink(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let oct = v4.octets();
                oct[0] == 10 && oct[1] == 10 && oct[2] == 34
            }
            IpAddr::V6(v6) => {
                let seg = v6.segments();
                seg[0] == 0x2001 && seg[1] == 0x4188 && seg[2] == 0x0002 && seg[3] == 0x0600
            }
        }
    }

    /// Shapes a TLS ClientHello packet across multiple fragmented TCP segments.
    ///
    /// Strategy:
    /// 1. Split at record header (byte 5) with 0ms delay.
    /// 2. Split at SNI offset (byte 43) with delay.
    /// 3. Split remainder into 1-byte chunks up to `max_split_tls`, with profile-determined delays.
    pub fn shape_client_hello(payload: &[u8], config: &ServerlessShaperConfig) -> Vec<ShaperFragment> {
        if payload.is_empty() {
            return Vec::new();
        }

        if payload.len() <= config.tls_record_split {
            return vec![ShaperFragment {
                payload: payload.to_vec(),
                delay_ms: 0,
            }];
        }

        let mut fragments = Vec::new();

        // 1. Record header (bytes 0..5)
        fragments.push(ShaperFragment {
            payload: payload[..config.tls_record_split].to_vec(),
            delay_ms: 0,
        });

        let mut curr_offset = config.tls_record_split;

        // 2. Handshake prefix up to SNI offset (bytes 5..43)
        let sni_boundary = config.sni_split_offset.min(payload.len());
        if sni_boundary > curr_offset {
            fragments.push(ShaperFragment {
                payload: payload[curr_offset..sni_boundary].to_vec(),
                delay_ms: Self::calculate_delay(0, config.profile),
            });
            curr_offset = sni_boundary;
        }

        // 3. Remainder split into small slices up to max_split_tls
        let mut slice_idx = 1usize;
        while curr_offset < payload.len() && curr_offset < config.max_split_tls {
            let chunk_len = 1.min(payload.len() - curr_offset);
            let delay = Self::calculate_delay(slice_idx, config.profile);
            fragments.push(ShaperFragment {
                payload: payload[curr_offset..curr_offset + chunk_len].to_vec(),
                delay_ms: delay,
            });
            curr_offset += chunk_len;
            slice_idx += 1;
        }

        // 4. Any leftover beyond max_split is emitted as a final contiguous slice
        if curr_offset < payload.len() {
            fragments.push(ShaperFragment {
                payload: payload[curr_offset..].to_vec(),
                delay_ms: Self::calculate_delay(slice_idx, config.profile),
            });
        }

        fragments
    }

    /// Shapes a generic TCP data packet into 1-byte fragments up to `max_split_tcp`.
    pub fn shape_tcp_stream(payload: &[u8], config: &ServerlessShaperConfig) -> Vec<ShaperFragment> {
        if payload.is_empty() {
            return Vec::new();
        }

        let mut fragments = Vec::new();
        let mut curr_offset = 0;
        let mut slice_idx = 0;

        while curr_offset < payload.len() && curr_offset < config.max_split_tcp {
            let chunk_len = 1.min(payload.len() - curr_offset);
            let delay = if curr_offset == 0 {
                0
            } else {
                Self::calculate_delay(slice_idx, config.profile)
            };
            fragments.push(ShaperFragment {
                payload: payload[curr_offset..curr_offset + chunk_len].to_vec(),
                delay_ms: delay,
            });
            curr_offset += chunk_len;
            slice_idx += 1;
        }

        if curr_offset < payload.len() {
            fragments.push(ShaperFragment {
                payload: payload[curr_offset..].to_vec(),
                delay_ms: Self::calculate_delay(slice_idx, config.profile),
            });
        }

        fragments
    }

    /// Computes the transmission delay in milliseconds for a fragment index.
    pub fn calculate_delay(slice_idx: usize, profile: ServerlessProfile) -> u64 {
        match profile {
            ServerlessProfile::LowDelay => 1,
            ServerlessProfile::HighDelay => {
                // Rhythmic 400ms stall every 10 slices, else 1ms
                if slice_idx > 0 && slice_idx % 10 == 0 {
                    400
                } else {
                    1
                }
            }
        }
    }

    /// Generates a randomized UDP noise payload if enabled.
    pub fn generate_udp_noise(counter: u32, config: &ServerlessShaperConfig) -> Option<Vec<u8>> {
        if !config.udp_noise_enabled {
            return None;
        }

        let len_range = if config.udp_noise_max_len > config.udp_noise_min_len {
            config.udp_noise_max_len - config.udp_noise_min_len
        } else {
            1
        };

        let target_len = config.udp_noise_min_len + ((counter as usize * 7) % len_range);
        let mut noise = vec![0u8; target_len];
        for (i, byte) in noise.iter_mut().enumerate() {
            *byte = ((counter as usize + i * 31) & 0xFF) as u8;
        }

        Some(noise)
    }
}
