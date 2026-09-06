//! Multi-Strategy TLS Fragmenter & Carrier Edge Selector
//!
//! Originates from UAC-SNI-Spoofer-Android-main (MciFragmenter & MciRouteSelector)
//! and absorbed into the LumiNet unified pure Rust evasion core.
//! Provides 10 discrete fragmentation strategies, dynamic SNI extension scanning,
//! TLS record payload encapsulation, FinalMask rewrite splitting, and multi-edge routing.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// 10 distinct fragmentation and record-splitting strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FragmentStrategy {
    /// FinalMask rewrite: splits TLS record into 2 records (first of `length` bytes, second remainder).
    FinalMaskTlsHello,
    /// Fixed 5-byte chunks across TCP segment boundaries.
    Full5,
    /// Fixed 10-byte chunks across TCP segment boundaries.
    Full10,
    /// Fixed 20-byte chunks across TCP segment boundaries.
    Full20,
    /// Splits TCP segment exactly at the start boundary of the SNI hostname.
    SniBoundary,
    /// Splits TCP segment in the middle of the SNI hostname.
    SniSplit,
    /// Splits TLS record payload in half, encapsulating each into valid TLS 0x16 records.
    TlsRecordFrag,
    /// Splits TLS record payload at the SNI offset, encapsulating both into valid TLS 0x16 records.
    TlsSniRecords,
    /// Splits raw byte buffer in half.
    Half,
    /// Raw passthrough without fragmentation.
    Raw,
}

/// Configuration settings for FinalMask TLS record rewriting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalMaskSettings {
    pub packet: String,
    pub length: usize,
    pub delay_ms: u32,
    pub max_split: usize,
}

impl Default for FinalMaskSettings {
    fn default() -> Self {
        Self {
            packet: "tlshello".to_string(),
            length: 5,
            delay_ms: 0,
            max_split: 2,
        }
    }
}

/// Result of rewriting a TLS packet using FinalMask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalMaskRewrite {
    pub first_write: Vec<u8>,
    pub trailing_write: Option<Vec<u8>>,
}

impl FinalMaskRewrite {
    pub fn writes(&self) -> Vec<Vec<u8>> {
        let mut list = vec![self.first_write.clone()];
        if let Some(ref trailing) = self.trailing_write {
            if !trailing.is_empty() {
                list.push(trailing.clone());
            }
        }
        list
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut out = self.first_write.clone();
        if let Some(ref trailing) = self.trailing_write {
            out.extend_from_slice(trailing);
        }
        out
    }
}

/// Traverses TLS ClientHello extensions to locate the SNI hostname byte range (offset, length).
pub fn locate_sni(data: &[u8]) -> Option<(usize, usize)> {
    if data.len() < 9 || data[0] != 0x16 {
        return None;
    }
    let record_len = ((data[3] as usize) << 8) | (data[4] as usize);
    let record_end = data.len().min(5 + record_len);

    let mut pos = 5;
    if pos >= record_end || data[pos] != 0x01 {
        return None; // Must be ClientHello
    }
    pos += 4 + 2 + 32; // handshake hdr (4) + version (2) + random (32)
    if pos >= record_end {
        return None;
    }

    let session_len = data[pos] as usize;
    pos += 1 + session_len;
    if pos + 2 > record_end {
        return None;
    }

    let cipher_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
    pos += 2 + cipher_len;
    if pos + 1 > record_end {
        return None;
    }

    let comp_len = data[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > record_end {
        return None;
    }

    let ext_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
    pos += 2;
    let ext_end = record_end.min(pos + ext_len);

    while pos + 4 <= ext_end {
        let ext_type = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
        let ext_data_len = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
        pos += 4;

        if ext_type == 0x0000 && pos + ext_data_len <= ext_end {
            // SNI extension found
            let mut name_pos = pos + 2; // skip server_name_list length (2 bytes)
            let names_end = pos + ext_data_len;
            while name_pos + 3 <= names_end {
                let name_type = data[name_pos];
                let name_len = ((data[name_pos + 1] as usize) << 8) | (data[name_pos + 2] as usize);
                name_pos += 3;
                if name_type == 0 && name_pos + name_len <= names_end {
                    return Some((name_pos, name_len));
                }
                name_pos += name_len;
            }
        }
        pos += ext_data_len;
    }

    None
}

/// Extracts the ASCII SNI hostname from a TLS ClientHello packet.
pub fn extract_sni(data: &[u8]) -> Option<String> {
    locate_sni(data).and_then(|(offset, len)| {
        if offset + len <= data.len() {
            String::from_utf8(data[offset..offset + len].to_vec()).ok()
        } else {
            None
        }
    })
}

/// Constructs a valid TLS record header (0x16, version, length) for payload encapsulation.
pub fn tls_record_frame(version: [u8; 2], payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0x16);
    frame.push(version[0]);
    frame.push(version[1]);
    frame.push(((payload.len() >> 8) & 0xff) as u8);
    frame.push((payload.len() & 0xff) as u8);
    frame.extend_from_slice(payload);
    frame
}

/// Splits a buffer into fixed-size chunks.
pub fn fixed_chunks(data: &[u8], size: usize) -> Vec<Vec<u8>> {
    if data.is_empty() {
        return vec![data.to_vec()];
    }
    let safe_size = size.max(1);
    data.chunks(safe_size).map(|chunk| chunk.to_vec()).collect()
}

/// Splits a buffer at a specified byte offset.
pub fn split_at(data: &[u8], requested: usize) -> Vec<Vec<u8>> {
    if data.len() < 2 {
        return vec![data.to_vec()];
    }
    let split = requested.clamp(1, data.len() - 1);
    vec![data[..split].to_vec(), data[split..].to_vec()]
}

/// Splits TLS record payload into two valid TLS records.
pub fn split_tls_record(data: &[u8], at_sni: bool) -> Vec<Vec<u8>> {
    if data.len() < 6 || data[0] != 0x16 {
        return vec![data.to_vec()];
    }
    let payload = &data[5..];
    if payload.len() < 2 {
        return vec![data.to_vec()];
    }

    let requested = if at_sni {
        if let Some((sni_offset, _)) = locate_sni(data) {
            sni_offset.saturating_sub(5)
        } else {
            payload.len() / 2
        }
    } else {
        payload.len() / 2
    };

    let split = requested.clamp(1, payload.len() - 1);
    let version = [data[1], data[2]];
    vec![
        tls_record_frame(version, &payload[..split]),
        tls_record_frame(version, &payload[split..]),
    ]
}

/// Rewrites a TLS ClientHello packet into two TLS records plus any trailing data.
pub fn rewrite_final_mask_writes(data: &[u8], settings: &FinalMaskSettings) -> FinalMaskRewrite {
    if settings.packet != "tlshello"
        || settings.length == 0
        || settings.max_split < 2
        || data.len() < 6
        || data[0] != 0x16
    {
        return FinalMaskRewrite {
            first_write: data.to_vec(),
            trailing_write: None,
        };
    }

    let record_len = ((data[3] as usize) << 8) | (data[4] as usize);
    let record_end = 5 + record_len;
    if record_len <= settings.length || record_end > data.len() {
        return FinalMaskRewrite {
            first_write: data.to_vec(),
            trailing_write: None,
        };
    }

    let version = [data[1], data[2]];
    let payload = &data[5..record_end];
    let first = tls_record_frame(version, &payload[..settings.length]);
    let second = tls_record_frame(version, &payload[settings.length..]);

    let mut combined_first = first;
    combined_first.extend_from_slice(&second);

    let trailing = if record_end < data.len() {
        Some(data[record_end..].to_vec())
    } else {
        None
    };

    FinalMaskRewrite {
        first_write: combined_first,
        trailing_write: trailing,
    }
}

/// Rewrites a TLS ClientHello packet using FinalMask and returns the contiguous byte representation.
pub fn rewrite_final_mask_tls_hello(data: &[u8], settings: &FinalMaskSettings) -> Vec<u8> {
    rewrite_final_mask_writes(data, settings).bytes()
}

/// Splits a packet using the requested `FragmentStrategy`.
pub fn fragment_packet(
    data: &[u8],
    strategy: FragmentStrategy,
    settings: &FinalMaskSettings,
) -> Vec<Vec<u8>> {
    match strategy {
        FragmentStrategy::FinalMaskTlsHello => rewrite_final_mask_writes(data, settings).writes(),
        FragmentStrategy::Full5 => fixed_chunks(data, 5),
        FragmentStrategy::Full10 => fixed_chunks(data, 10),
        FragmentStrategy::Full20 => fixed_chunks(data, 20),
        FragmentStrategy::SniBoundary => {
            if let Some((offset, _)) = locate_sni(data) {
                split_at(data, offset)
            } else {
                split_at(data, data.len() / 2)
            }
        }
        FragmentStrategy::SniSplit => {
            if let Some((offset, len)) = locate_sni(data) {
                split_at(data, offset + (len / 2).max(1))
            } else {
                split_at(data, data.len() / 2)
            }
        }
        FragmentStrategy::TlsRecordFrag => split_tls_record(data, false),
        FragmentStrategy::TlsSniRecords => split_tls_record(data, true),
        FragmentStrategy::Half => split_at(data, data.len() / 2),
        FragmentStrategy::Raw => vec![data.to_vec()],
    }
}

/// Carrier Edge Node Profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarrierEdgeProfile {
    pub address: String,
    pub port: u16,
    pub role: String,
    pub finalmask_max_split: usize,
}

impl CarrierEdgeProfile {
    pub fn new(address: &str, port: u16, role: &str, finalmask_max_split: usize) -> Self {
        Self {
            address: address.to_string(),
            port,
            role: role.to_string(),
            finalmask_max_split,
        }
    }
}

/// Autonomous carrier route selector with failure cooldown and priority ordering.
#[derive(Debug, Clone)]
pub struct CarrierRouteSelector {
    cooldown_duration: Duration,
    failed_until: HashMap<String, Instant>,
}

impl CarrierRouteSelector {
    pub fn new(cooldown_duration: Duration) -> Self {
        Self {
            cooldown_duration,
            failed_until: HashMap::new(),
        }
    }

    pub fn default_mci_selector() -> Self {
        Self::new(Duration::from_millis(12_000))
    }

    /// Partitions edges into healthy and cooling down, returning healthy nodes first.
    pub fn ordered_edges(&self, edges: &[CarrierEdgeProfile]) -> Vec<CarrierEdgeProfile> {
        let now = Instant::now();
        let mut healthy = Vec::new();
        let mut cooling_down = Vec::new();

        for edge in edges {
            if let Some(&until) = self.failed_until.get(&edge.address) {
                if until > now {
                    cooling_down.push(edge.clone());
                    continue;
                }
            }
            healthy.push(edge.clone());
        }

        healthy.extend(cooling_down);
        healthy
    }

    /// Records an edge node failure, setting cooldown timer.
    pub fn record_failure(&mut self, edge: &CarrierEdgeProfile) {
        self.failed_until
            .insert(edge.address.clone(), Instant::now() + self.cooldown_duration);
    }

    /// Records an edge node success, clearing failure timer immediately.
    pub fn record_success(&mut self, edge: &CarrierEdgeProfile) {
        self.failed_until.remove(&edge.address);
    }

    /// Returns whether an edge is currently in cooldown.
    pub fn is_in_cooldown(&self, edge: &CarrierEdgeProfile) -> bool {
        if let Some(&until) = self.failed_until.get(&edge.address) {
            until > Instant::now()
        } else {
            false
        }
    }
}
