//! # Unified Fragmentation
//!
//! Merges: tls_fragment::FragmentConfig (profile-based) + tls_http_evasion::TlsFragmentConfig (fixed-size).
//! Supports both SNI-aware profile-based splitting AND fixed-size TLS record fragmentation.

use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;

/// Fragmentation profile strategy.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FragmentProfile {
    /// No fragmentation, pass through as-is.
    Passthrough,
    /// Split at the midpoint of the data.
    EqualSplit,
    /// Split at the start of the SNI field in TLS ClientHello.
    SniDerived,
    /// Split just before the SNI field.
    SniPrefixed,
    /// Split at multiple points for maximum DPI confusion.
    MultiSplit,
    /// Fixed-size fragmentation.
    FixedSize,
}

/// Unified fragmentation configuration.
/// Combines profile-based (SNI-aware) and fixed-size (TLS record) fragmentation.
#[derive(Debug, Clone)]
pub struct FragmentConfig {
    /// Fragmentation profile.
    pub profile: FragmentProfile,
    /// Delay between fragments in milliseconds.
    pub delay_ms: u64,
    /// Minimum fragment size (for profile-based).
    pub min_size: usize,
    /// Maximum fragment size (for profile-based).
    pub max_size: usize,
    /// Fixed fragment size (for FixedSize profile).
    pub fixed_size: usize,
    /// TCP segment size for additional splitting.
    pub tcp_segment_size: usize,
    /// Spoof TLS version in record headers.
    pub spoof_version: bool,
    /// Fake TLS version to use (e.g., 0x0300 for SSL 3.0).
    pub fake_version: u16,
}

impl Default for FragmentConfig {
    fn default() -> Self {
        Self {
            profile: FragmentProfile::SniDerived,
            delay_ms: 10,
            min_size: 1,
            max_size: 2048,
            fixed_size: 20,
            tcp_segment_size: 0,
            spoof_version: false,
            fake_version: 0x0300,
        }
    }
}

impl FragmentConfig {
    /// Creates a config for SNI-aware fragmentation.
    pub fn sni_aware() -> Self {
        Self {
            profile: FragmentProfile::SniDerived,
            delay_ms: 10,
            ..Default::default()
        }
    }

    /// Creates a config for fixed-size TLS record fragmentation.
    pub fn fixed_size(frag_size: usize) -> Self {
        Self {
            profile: FragmentProfile::FixedSize,
            fixed_size: frag_size,
            ..Default::default()
        }
    }

    /// Creates a config with version spoofing enabled.
    pub fn with_version_spoof(version: u16) -> Self {
        Self {
            profile: FragmentProfile::FixedSize,
            spoof_version: true,
            fake_version: version,
            ..Default::default()
        }
    }
}

/// Finds the SNI byte range in a TLS ClientHello.
/// Returns (start, end) byte offsets of the SNI hostname.
pub fn find_sni_range(data: &[u8]) -> Option<(usize, usize)> {
    if data.len() < 5 || data[0] != 0x16 {
        return None;
    }

    let mut pos = 5; // Skip record header
    if pos + 4 > data.len() {
        return None;
    }
    pos += 4; // Skip handshake header
    pos += 34; // Skip version + random
    if pos >= data.len() {
        return None;
    }

    // Session ID
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites
    if pos + 2 > data.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cipher_len;

    // Compression
    if pos >= data.len() {
        return None;
    }
    let comp_len = data[pos] as usize;
    pos += 1 + comp_len;

    // Extensions
    if pos + 2 > data.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;

    while pos + 4 <= ext_end && pos + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension
            if pos + 2 > data.len() {
                return None;
            }
            let sni_start = pos + 2;
            if sni_start + 3 > data.len() {
                return None;
            }
            let sni_len = u16::from_be_bytes([data[sni_start + 1], data[sni_start + 2]]) as usize;
            let sni_value_start = sni_start + 3;
            if sni_value_start + sni_len <= data.len() {
                return Some((sni_value_start, sni_value_start + sni_len));
            }
        }
        pos += ext_len;
    }

    None
}

/// Computes split points based on the fragmentation profile.
pub fn compute_splits(data: &[u8], config: &FragmentConfig) -> Vec<usize> {
    match config.profile {
        FragmentProfile::Passthrough => vec![],
        FragmentProfile::EqualSplit => vec![data.len() / 2],
        FragmentProfile::SniDerived => {
            if let Some((start, _)) = find_sni_range(data) {
                vec![start]
            } else {
                vec![data.len() / 2]
            }
        }
        FragmentProfile::SniPrefixed => {
            if let Some((start, _)) = find_sni_range(data) {
                vec![start.saturating_sub(2)]
            } else {
                vec![data.len() / 2]
            }
        }
        FragmentProfile::MultiSplit => {
            let mut splits = vec![data.len() / 4, data.len() / 2, data.len() * 3 / 4];
            if let Some((start, _)) = find_sni_range(data) {
                splits.push(start);
            }
            splits.sort();
            splits.dedup();
            splits
        }
        FragmentProfile::FixedSize => {
            let mut splits = Vec::new();
            let mut pos = config.fixed_size;
            while pos < data.len() {
                splits.push(pos);
                pos += config.fixed_size;
            }
            splits
        }
    }
}

/// Sends data with fragmentation.
pub fn send_fragmented(
    stream: &mut TcpStream,
    data: &[u8],
    config: &FragmentConfig,
) -> std::io::Result<()> {
    let splits = compute_splits(data, config);

    if splits.is_empty() {
        stream.write_all(data)?;
        return Ok(());
    }

    let mut offset = 0;
    for split in &splits {
        let split = (*split).min(data.len());
        if split <= offset {
            continue;
        }

        stream.write_all(&data[offset..split])?;
        stream.flush()?;

        if config.delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(config.delay_ms));
        }
        offset = split;
    }

    if offset < data.len() {
        stream.write_all(&data[offset..])?;
        stream.flush()?;
    }

    Ok(())
}

/// Fragments a TLS record into multiple smaller records.
/// Each fragment gets a valid TLS record header.
pub fn fragment_tls_record(
    record_header: &[u8],
    record_body: &[u8],
    config: &FragmentConfig,
) -> Vec<u8> {
    let mut fragmented = Vec::new();
    let header = if record_header.len() >= 5 {
        record_header[..5].to_vec()
    } else {
        vec![0x16, 0x03, 0x01, 0x00, 0x00]
    };

    let mut offset = 0;
    while offset < record_body.len() {
        let end = (offset + config.fixed_size).min(record_body.len());
        let fragment = &record_body[offset..end];

        let mut frag_header = header.clone();
        let len = fragment.len() as u16;
        frag_header[3] = (len >> 8) as u8;
        frag_header[4] = (len & 0xFF) as u8;

        // Version spoofing
        if config.spoof_version {
            frag_header[1] = (config.fake_version >> 8) as u8;
            frag_header[2] = (config.fake_version & 0xFF) as u8;
        }

        fragmented.extend_from_slice(&frag_header);
        fragmented.extend_from_slice(fragment);
        offset = end;
    }

    fragmented
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = FragmentConfig::default();
        assert_eq!(config.profile, FragmentProfile::SniDerived);
        assert_eq!(config.delay_ms, 10);
    }

    #[test]
    fn test_sni_aware_config() {
        let config = FragmentConfig::sni_aware();
        assert_eq!(config.profile, FragmentProfile::SniDerived);
    }

    #[test]
    fn test_fixed_size_config() {
        let config = FragmentConfig::fixed_size(20);
        assert_eq!(config.profile, FragmentProfile::FixedSize);
        assert_eq!(config.fixed_size, 20);
    }

    #[test]
    fn test_version_spoof_config() {
        let config = FragmentConfig::with_version_spoof(0x0300);
        assert!(config.spoof_version);
        assert_eq!(config.fake_version, 0x0300);
    }

    #[test]
    fn test_compute_splits_fixed_size() {
        let data = vec![0u8; 100];
        let config = FragmentConfig::fixed_size(20);
        let splits = compute_splits(&data, &config);
        assert_eq!(splits.len(), 4); // 20, 40, 60, 80
    }

    #[test]
    fn test_compute_splits_passthrough() {
        let data = vec![0u8; 100];
        let config = FragmentConfig {
            profile: FragmentProfile::Passthrough,
            ..Default::default()
        };
        let splits = compute_splits(&data, &config);
        assert!(splits.is_empty());
    }
}
