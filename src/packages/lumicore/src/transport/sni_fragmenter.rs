//! 3-Zone TLS SNI Fragmentation & Evasion Planner.
//!
//! Ported and unified from `bepass-main`.
//! Parses TLS ClientHello packets, locates the SNI extension boundaries, and decomposes
//! the handshake into sub-packet fragments across three distinct zones:
//!   - Zone 0: Pre-SNI ClientHello header
//!   - Zone 1: SNI Hostname bytes
//!   - Zone 2: Post-SNI CipherSuites & Extension tail
//! Injecting configurable inter-packet delays to defeat stateful Deep Packet Inspection (DPI).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SniFragmentConfig {
    pub before_sni_range: (usize, usize),
    pub sni_range: (usize, usize),
    pub after_sni_range: (usize, usize),
    pub delay_ms_range: (u64, u64),
}

impl Default for SniFragmentConfig {
    fn default() -> Self {
        Self {
            before_sni_range: (1, 5),
            sni_range: (1, 3),
            after_sni_range: (5, 20),
            delay_ms_range: (1, 5),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FragmentSlice {
    pub zone: String,
    pub payload: Vec<u8>,
    pub delay_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SniFragmentPlan {
    pub slices: Vec<FragmentSlice>,
    pub total_bytes: usize,
    pub detected_sni: Option<String>,
}

pub struct SniFragmenter;

impl SniFragmenter {
    /// Extracts the Server Name Indication (SNI) string from a raw TLS ClientHello packet.
    pub fn extract_sni(packet: &[u8]) -> Option<String> {
        Self::locate_sni(packet).map(|(_, _, name)| name)
    }

    /// Locates the byte offset range `(start, end, server_name)` of the SNI inside the packet.
    pub fn locate_sni(packet: &[u8]) -> Option<(usize, usize, String)> {
        // Minimum TLS Record + Handshake header length
        if packet.len() < 5 + 4 + 2 + 32 + 1 {
            return None;
        }

        // Record header: ContentType (0x16 = Handshake), Version (0x0301 or 0x0303)
        if packet[0] != 0x16 {
            return None;
        }

        let record_len = u16::from_be_bytes([packet[3], packet[4]]) as usize;
        if packet.len() < 5 + record_len {
            return None;
        }

        let mut offset = 5;

        // Handshake type (0x01 = ClientHello)
        if packet[offset] != 0x01 {
            return None;
        }
        let handshake_len = ((packet[offset + 1] as usize) << 16)
            | ((packet[offset + 2] as usize) << 8)
            | (packet[offset + 3] as usize);
        if packet.len() < offset + 4 + handshake_len {
            return None;
        }
        offset += 4;

        // ClientHello: Version (2B) + Random (32B)
        if packet.len() < offset + 2 + 32 + 1 {
            return None;
        }
        offset += 2 + 32;

        // Session ID
        let session_id_len = packet[offset] as usize;
        offset += 1;
        if packet.len() < offset + session_id_len + 2 {
            return None;
        }
        offset += session_id_len;

        // Cipher Suites
        let cipher_suites_len = u16::from_be_bytes([packet[offset], packet[offset + 1]]) as usize;
        offset += 2;
        if packet.len() < offset + cipher_suites_len + 1 {
            return None;
        }
        offset += cipher_suites_len;

        // Compression Methods
        let compression_len = packet[offset] as usize;
        offset += 1;
        if packet.len() < offset + compression_len + 2 {
            return None;
        }
        offset += compression_len;

        // Extensions
        let extensions_len = u16::from_be_bytes([packet[offset], packet[offset + 1]]) as usize;
        offset += 2;
        let extensions_end = offset + extensions_len;
        if packet.len() < extensions_end {
            return None;
        }

        while offset + 4 <= extensions_end {
            let ext_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
            let ext_len = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) as usize;
            offset += 4;

            if offset + ext_len > extensions_end {
                break;
            }

            if ext_type == 0x0000 {
                // Server Name extension
                if ext_len < 5 {
                    return None;
                }
                let list_len = u16::from_be_bytes([packet[offset], packet[offset + 1]]) as usize;
                let mut list_off = offset + 2;
                let list_end = offset + 2 + list_len;

                while list_off + 3 <= list_end {
                    let name_type = packet[list_off];
                    let name_len = u16::from_be_bytes([packet[list_off + 1], packet[list_off + 2]]) as usize;
                    list_off += 3;

                    if list_off + name_len > list_end {
                        break;
                    }

                    if name_type == 0x00 {
                        // Hostname
                        let name_bytes = &packet[list_off..list_off + name_len];
                        if let Ok(name) = std::str::from_utf8(name_bytes) {
                            return Some((list_off, list_off + name_len, name.to_string()));
                        }
                    }
                    list_off += name_len;
                }
            }

            offset += ext_len;
        }

        None
    }

    /// Plans the 3-zone fragment slices and delays for a packet.
    pub fn plan_fragments(packet: &[u8], config: &SniFragmentConfig) -> SniFragmentPlan {
        let mut slices = Vec::new();

        if let Some((sni_start, sni_end, sni_name)) = Self::locate_sni(packet) {
            // Zone 0: Before SNI
            let before_bytes = &packet[..sni_start];
            Self::chunk_zone(before_bytes, config.before_sni_range, config.delay_ms_range, "before_sni", &mut slices);

            // Zone 1: SNI Hostname
            let sni_bytes = &packet[sni_start..sni_end];
            Self::chunk_zone(sni_bytes, config.sni_range, config.delay_ms_range, "sni", &mut slices);

            // Zone 2: After SNI
            let after_bytes = &packet[sni_end..];
            Self::chunk_zone(after_bytes, config.after_sni_range, config.delay_ms_range, "after_sni", &mut slices);

            let total_bytes = slices.iter().map(|s| s.payload.len()).sum();
            SniFragmentPlan {
                slices,
                total_bytes,
                detected_sni: Some(sni_name),
            }
        } else {
            // No SNI detected -> single pass-through or simple chunking
            slices.push(FragmentSlice {
                zone: "passthrough".to_string(),
                payload: packet.to_vec(),
                delay_ms: 0,
            });
            SniFragmentPlan {
                slices,
                total_bytes: packet.len(),
                detected_sni: None,
            }
        }
    }

    fn chunk_zone(
        zone_bytes: &[u8],
        range: (usize, usize),
        delay_range: (u64, u64),
        zone_name: &'static str,
        out: &mut Vec<FragmentSlice>,
    ) {
        if zone_bytes.is_empty() {
            return;
        }

        let (min_chunk, max_chunk) = if range.0 == 0 || range.1 < range.0 {
            (1, std::cmp::max(1, range.1))
        } else {
            range
        };

        let (min_delay, max_delay) = if delay_range.1 < delay_range.0 {
            (delay_range.0, delay_range.0)
        } else {
            delay_range
        };

        let mut offset = 0;
        let mut step = 0usize;

        while offset < zone_bytes.len() {
            // Deterministic chunk sizing within [min_chunk, max_chunk] to ensure reproducible testing
            let span = max_chunk - min_chunk + 1;
            let chunk_size = min_chunk + (step % span);
            let end = std::cmp::min(offset + chunk_size, zone_bytes.len());

            let delay_span = max_delay - min_delay + 1;
            let delay_ms = min_delay + ((step as u64) % delay_span);

            out.push(FragmentSlice {
                zone: zone_name.to_string(),
                payload: zone_bytes[offset..end].to_vec(),
                delay_ms,
            });

            offset = end;
            step += 1;
        }
    }
}
