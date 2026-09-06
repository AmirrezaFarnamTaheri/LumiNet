//! Adaptive Strategy Racer & Disposable Fake SNI Probe Engine
//!
//! into LumiNet pure Rust evasion core.
//! Provides granular `SniChars` fragmentation (1 byte per SNI character),
//! `Multi64` chunking, middlebox TLS response validation (alert & malformed rejection),
//! disposable fake ClientHello probe synthesis, and carrier-specific adaptive strategy racing.

use std::collections::HashMap;

/// Extended fragmentation strategies including byte-per-character SNI splitting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtendedFragmentStrategy {
    /// Each character of the SNI hostname is sent in an individual 1-byte TCP segment.
    SniChars,
    /// Fixed 64-byte chunks.
    Multi64,
    /// Fixed 5-byte chunks.
    Full5,
    /// Fixed 10-byte chunks.
    Full10,
    /// Fixed 20-byte chunks.
    Full20,
    /// Boundary at SNI offset.
    SniBoundary,
    /// Boundary in middle of SNI.
    SniSplit,
    /// TLS record payload split into two valid TLS 0x16 records.
    TlsRecordFrag,
    /// TLS record payload split at SNI into two valid TLS 0x16 records.
    TlsSniRecords,
    /// Half buffer split.
    Half,
    /// Raw unmodified buffer.
    Raw,
}

impl ExtendedFragmentStrategy {
    pub fn name(&self) -> &'static str {
        match self {
            Self::SniChars => "sni_chars",
            Self::Multi64 => "multi64",
            Self::Full5 => "full5",
            Self::Full10 => "full10",
            Self::Full20 => "full20",
            Self::SniBoundary => "sni_boundary",
            Self::SniSplit => "sni_split",
            Self::TlsRecordFrag => "tls_record_frag",
            Self::TlsSniRecords => "tls_sni_records",
            Self::Half => "half",
            Self::Raw => "raw",
        }
    }
}

/// Status of the server's initial TLS response to a fragmented ClientHello.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrategyResponseStatus {
    /// Valid ServerHello or handshake response.
    Valid,
    /// Empty response from remote host (connection dropped or filtered).
    EmptyResponse,
    /// Middlebox or server returned TLS Alert record (0x15).
    AlertRejected,
    /// Truncated or corrupt record (< 8 bytes with type 0x14, 0x16, or 0x17).
    TruncatedMalformed,
}

/// Validates server response to detect middlebox RST/Alert or corrupted handshakes.
pub fn validate_strategy_response(response: &[u8]) -> StrategyResponseStatus {
    if response.is_empty() {
        return StrategyResponseStatus::EmptyResponse;
    }
    let first_byte = response[0];
    if first_byte == 0x15 {
        return StrategyResponseStatus::AlertRejected;
    }
    if response.len() < 8 && (first_byte == 0x14 || first_byte == 0x16 || first_byte == 0x17) {
        return StrategyResponseStatus::TruncatedMalformed;
    }
    StrategyResponseStatus::Valid
}

/// Traverses TLS ClientHello extensions to locate the SNI hostname byte range (offset, length).
pub fn locate_sni_range(data: &[u8]) -> Option<(usize, usize)> {
    if data.len() < 9 || data[0] != 0x16 {
        return None;
    }
    let record_len = ((data[3] as usize) << 8) | (data[4] as usize);
    let record_end = data.len().min(5 + record_len);

    let mut pos = 5;
    if pos >= record_end || data[pos] != 0x01 {
        return None;
    }
    pos += 4 + 2 + 32; // handshake (4) + version (2) + random (32)
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
            let mut name_pos = pos + 2;
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

/// Constructs a valid TLS record header for payload encapsulation.
fn tls_record(version: [u8; 2], payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0x16);
    frame.push(version[0]);
    frame.push(version[1]);
    frame.push(((payload.len() >> 8) & 0xff) as u8);
    frame.push((payload.len() & 0xff) as u8);
    frame.extend_from_slice(payload);
    frame
}

/// Fragments data according to an `ExtendedFragmentStrategy`.
pub fn fragment_extended(
    data: &[u8],
    strategy: ExtendedFragmentStrategy,
    chunk_size: usize,
) -> Vec<Vec<u8>> {
    if data.len() < 2 {
        return vec![data.to_vec()];
    }

    let location = locate_sni_range(data);

    match strategy {
        ExtendedFragmentStrategy::Raw => vec![data.to_vec()],
        ExtendedFragmentStrategy::Half => {
            let cut = (data.len() / 2).max(1);
            vec![data[..cut].to_vec(), data[cut..].to_vec()]
        }
        ExtendedFragmentStrategy::Full5 => {
            data.chunks(5).map(|c| c.to_vec()).collect()
        }
        ExtendedFragmentStrategy::Full10 => {
            data.chunks(10).map(|c| c.to_vec()).collect()
        }
        ExtendedFragmentStrategy::Full20 => {
            data.chunks(20).map(|c| c.to_vec()).collect()
        }
        ExtendedFragmentStrategy::Multi64 => {
            let size = if chunk_size > 0 { chunk_size } else { 64 };
            data.chunks(size).map(|c| c.to_vec()).collect()
        }
        ExtendedFragmentStrategy::SniBoundary => {
            if let Some((start, _)) = location {
                let cut = start.clamp(1, data.len() - 1);
                vec![data[..cut].to_vec(), data[cut..].to_vec()]
            } else {
                let cut = (data.len() / 2).max(1);
                vec![data[..cut].to_vec(), data[cut..].to_vec()]
            }
        }
        ExtendedFragmentStrategy::SniSplit => {
            if let Some((start, length)) = location {
                let cut = (start + (length / 2).max(1)).clamp(1, data.len() - 1);
                vec![data[..cut].to_vec(), data[cut..].to_vec()]
            } else {
                let cut = (data.len() / 2).max(1);
                vec![data[..cut].to_vec(), data[cut..].to_vec()]
            }
        }
        ExtendedFragmentStrategy::SniChars => {
            if let Some((start, length)) = location {
                let mut out = Vec::new();
                if start > 0 {
                    out.push(data[..start].to_vec());
                }
                for i in 0..length {
                    out.push(vec![data[start + i]]);
                }
                if start + length < data.len() {
                    out.push(data[start + length..].to_vec());
                }
                out
            } else {
                let cut = (data.len() / 2).max(1);
                vec![data[..cut].to_vec(), data[cut..].to_vec()]
            }
        }
        ExtendedFragmentStrategy::TlsRecordFrag | ExtendedFragmentStrategy::TlsSniRecords => {
            if data[0] == 0x16 && data.len() > 5 {
                let payload = &data[5..];
                let version = [data[1], data[2]];
                let split = if strategy == ExtendedFragmentStrategy::TlsSniRecords {
                    if let Some((start, _)) = location {
                        start.saturating_sub(5).clamp(1, payload.len() - 1)
                    } else {
                        (payload.len() / 2).max(1)
                    }
                } else {
                    (payload.len() / 2).max(1)
                };
                vec![
                    tls_record(version, &payload[..split]),
                    tls_record(version, &payload[split..]),
                ]
            } else {
                vec![data.to_vec()]
            }
        }
    }
}

/// Synthesizes a disposable RFC 8446 compliant TLS 1.3 ClientHello with fake SNI and ALPN.
pub fn build_disposable_fake_probe(fake_sni: &str) -> Vec<u8> {
    let host_bytes = fake_sni.as_bytes();
    let mut pkt = Vec::with_capacity(256 + host_bytes.len());

    // Record header
    pkt.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x00]);

    let handshake_start = pkt.len();
    pkt.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // ClientHello
    pkt.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

    // 32-byte pseudo-random
    for i in 0..32 {
        pkt.push(((i * 37 + 11) & 0xff) as u8);
    }

    pkt.push(0x00); // session id len 0

    // Cipher suites: TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256
    pkt.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x03]);
    pkt.extend_from_slice(&[0x01, 0x00]); // compression null

    let ext_len_pos = pkt.len();
    pkt.extend_from_slice(&[0x00, 0x00]);
    let ext_start = pkt.len();

    // Extension: SNI
    let sni_ext_len = 2 + 1 + 2 + host_bytes.len();
    pkt.extend_from_slice(&[
        0x00, 0x00,
        ((sni_ext_len >> 8) & 0xff) as u8,
        (sni_ext_len & 0xff) as u8,
        (((sni_ext_len - 2) >> 8) & 0xff) as u8,
        ((sni_ext_len - 2) & 0xff) as u8,
        0x00,
        ((host_bytes.len() >> 8) & 0xff) as u8,
        (host_bytes.len() & 0xff) as u8,
    ]);
    pkt.extend_from_slice(host_bytes);

    // Extension: ALPN (http/1.1, h2)
    pkt.extend_from_slice(&[
        0x00, 0x10, // ALPN extension type
        0x00, 0x0e, // extension length (14)
        0x00, 0x0c, // list length (12)
        0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1', // http/1.1
        0x02, b'h', b'2', // h2
    ]);

    // Fill extensions length
    let ext_len = pkt.len() - ext_start;
    pkt[ext_len_pos] = ((ext_len >> 8) & 0xff) as u8;
    pkt[ext_len_pos + 1] = (ext_len & 0xff) as u8;

    // Fill handshake length
    let hs_len = pkt.len() - handshake_start - 4;
    pkt[handshake_start + 1] = ((hs_len >> 16) & 0xff) as u8;
    pkt[handshake_start + 2] = ((hs_len >> 8) & 0xff) as u8;
    pkt[handshake_start + 3] = (hs_len & 0xff) as u8;

    // Fill record length
    let rec_len = pkt.len() - 5;
    pkt[3] = ((rec_len >> 8) & 0xff) as u8;
    pkt[4] = (rec_len & 0xff) as u8;

    pkt
}

/// Carrier Mode for tuning strategy racing priorities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierMode {
    Mci,
    Irancell,
    Adaptive,
}

/// Adaptive Strategy Racer state tracker.
#[derive(Debug, Clone)]
pub struct AdaptiveStrategyRacer {
    carrier_mode: CarrierMode,
    preferred_strategies: HashMap<String, ExtendedFragmentStrategy>,
    fake_probe_enabled: bool,
    fake_sni: String,
}

impl AdaptiveStrategyRacer {
    pub fn new(carrier_mode: CarrierMode, fake_sni: &str) -> Self {
        Self {
            carrier_mode,
            preferred_strategies: HashMap::new(),
            fake_probe_enabled: true,
            fake_sni: fake_sni.to_string(),
        }
    }

    /// Generates the prioritized strategy plan (strategy, delay_ms) for a target host.
    pub fn plan_strategies(&self, host: &str) -> Vec<(ExtendedFragmentStrategy, u32)> {
        let mut list = match self.carrier_mode {
            CarrierMode::Mci => vec![
                (ExtendedFragmentStrategy::Full20, 1),
                (ExtendedFragmentStrategy::Full10, 2),
                (ExtendedFragmentStrategy::Full5, 5),
                (ExtendedFragmentStrategy::SniChars, 2),
                (ExtendedFragmentStrategy::SniBoundary, 1),
                (ExtendedFragmentStrategy::SniSplit, 3),
                (ExtendedFragmentStrategy::TlsRecordFrag, 3),
                (ExtendedFragmentStrategy::TlsSniRecords, 3),
                (ExtendedFragmentStrategy::Half, 3),
                (ExtendedFragmentStrategy::Raw, 0),
            ],
            CarrierMode::Irancell => vec![
                (ExtendedFragmentStrategy::Multi64, 0),
                (ExtendedFragmentStrategy::SniBoundary, 0),
                (ExtendedFragmentStrategy::TlsRecordFrag, 1),
                (ExtendedFragmentStrategy::SniChars, 1),
                (ExtendedFragmentStrategy::SniSplit, 2),
                (ExtendedFragmentStrategy::Half, 2),
                (ExtendedFragmentStrategy::Raw, 0),
            ],
            CarrierMode::Adaptive => vec![
                (ExtendedFragmentStrategy::SniSplit, 2),
                (ExtendedFragmentStrategy::SniBoundary, 1),
                (ExtendedFragmentStrategy::SniChars, 1),
                (ExtendedFragmentStrategy::TlsSniRecords, 2),
                (ExtendedFragmentStrategy::TlsRecordFrag, 2),
                (ExtendedFragmentStrategy::Multi64, 0),
                (ExtendedFragmentStrategy::Half, 2),
                (ExtendedFragmentStrategy::Raw, 0),
            ],
        };

        if let Some(&preferred) = self.preferred_strategies.get(host) {
            list.sort_by_key(|(strat, _)| *strat != preferred);
        }

        list
    }

    /// Records strategy success for a host.
    pub fn record_success(&mut self, host: &str, strategy: ExtendedFragmentStrategy) {
        self.preferred_strategies.insert(host.to_string(), strategy);
    }

    /// Returns the preferred strategy for a host if established.
    pub fn preferred_strategy(&self, host: &str) -> Option<ExtendedFragmentStrategy> {
        self.preferred_strategies.get(host).copied()
    }

    /// Generates disposable fake probe if enabled.
    pub fn build_fake_probe(&self) -> Option<Vec<u8>> {
        if self.fake_probe_enabled && !self.fake_sni.is_empty() {
            Some(build_disposable_fake_probe(&self.fake_sni))
        } else {
            None
        }
    }
}
