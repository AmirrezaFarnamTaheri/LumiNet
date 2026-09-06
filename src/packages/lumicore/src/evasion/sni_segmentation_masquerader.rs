//! # SNI Segmentation Masquerader
//!
//! Evasive TLS stream transformer that identifies TLS ClientHello SNI extensions
//! and segments them across randomized TCP chunk boundaries to evade deep packet inspection.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentationStrategy {
    SniBorderSplit,
    MidSniSplit,
    RandomSplit,
}

pub struct SniSegmentationMasquerader {
    strategy: SegmentationStrategy,
    min_chunk_size: usize,
    max_chunk_size: usize,
}

impl SniSegmentationMasquerader {
    pub fn new(strategy: SegmentationStrategy, min_chunk_size: usize, max_chunk_size: usize) -> Self {
        Self {
            strategy,
            min_chunk_size: min_chunk_size.max(2),
            max_chunk_size: max_chunk_size.max(min_chunk_size + 1),
        }
    }

    pub fn extract_sni(&self, data: &[u8]) -> Option<(String, usize, usize)> {
        // Minimum TLS ClientHello length
        if data.len() < 43 || data[0] != 0x16 {
            return None;
        }

        // Search for SNI extension type 0x00, 0x00
        // Standard TLS 1.2 / 1.3 ClientHello scan
        let mut idx = 43; // skip past record header (5) + handshake type/len (4) + version (2) + random (32)
        if idx >= data.len() {
            return None;
        }

        // Skip session ID
        let session_id_len = data[idx] as usize;
        idx += 1 + session_id_len;
        if idx + 2 >= data.len() {
            return None;
        }

        // Skip cipher suites
        let cipher_len = u16::from_be_bytes([data[idx], data[idx + 1]]) as usize;
        idx += 2 + cipher_len;
        if idx + 1 >= data.len() {
            return None;
        }

        // Skip compression methods
        let comp_len = data[idx] as usize;
        idx += 1 + comp_len;
        if idx + 2 >= data.len() {
            return None;
        }

        // Extensions length
        let ext_len = u16::from_be_bytes([data[idx], data[idx + 1]]) as usize;
        idx += 2;
        let ext_end = (idx + ext_len).min(data.len());

        while idx + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([data[idx], data[idx + 1]]);
            let ext_size = u16::from_be_bytes([data[idx + 2], data[idx + 3]]) as usize;
            idx += 4;

            if ext_type == 0 {
                // Server Name extension
                if idx + ext_size <= ext_end && ext_size >= 5 {
                    let sni_name_len = u16::from_be_bytes([data[idx + 3], data[idx + 4]]) as usize;
                    let sni_start = idx + 5;
                    let sni_end = sni_start + sni_name_len;
                    if sni_end <= idx + ext_size {
                        let sni = String::from_utf8_lossy(&data[sni_start..sni_end]).to_string();
                        return Some((sni, sni_start, sni_end));
                    }
                }
            }
            idx += ext_size;
        }

        None
    }

    pub fn segment_stream(&self, data: &[u8], seed: u64) -> Vec<Vec<u8>> {
        if data.is_empty() {
            return Vec::new();
        }

        if let Some((_sni, start, end)) = self.extract_sni(data) {
            match self.strategy {
                SegmentationStrategy::SniBorderSplit => {
                    let mut chunks = Vec::new();
                    if start > 0 {
                        chunks.push(data[..start].to_vec());
                    }
                    chunks.push(data[start..end].to_vec());
                    if end < data.len() {
                        chunks.push(data[end..].to_vec());
                    }
                    return chunks;
                }
                SegmentationStrategy::MidSniSplit => {
                    let mid = start + (end - start) / 2;
                    let mut chunks = Vec::new();
                    chunks.push(data[..mid].to_vec());
                    chunks.push(data[mid..].to_vec());
                    return chunks;
                }
                SegmentationStrategy::RandomSplit => {
                    // Fallthrough to random chunking
                }
            }
        }

        // Default or random chunking
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let mut chunks = Vec::new();
        let mut curr = 0;

        while curr < data.len() {
            let remaining = data.len() - curr;
            let step = if remaining <= self.min_chunk_size {
                remaining
            } else {
                let range = (self.max_chunk_size - self.min_chunk_size).max(1);
                (self.min_chunk_size + (rng.gen::<usize>() % range)).min(remaining)
            };

            chunks.push(data[curr..curr + step].to_vec());
            curr += step;
        }

        chunks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_dummy_tls_hello(sni: &str) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(0x16); // Handshake
        data.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record
        data.extend_from_slice(&[0x00, 0x00]); // Length placeholder

        // Handshake header
        data.push(0x01); // ClientHello
        data.extend_from_slice(&[0x00, 0x00, 0x00]); // Handshake len placeholder
        data.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        data.extend_from_slice(&[0u8; 32]); // Random

        // Session ID
        data.push(0x00);

        // Cipher suites
        data.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);

        // Compression
        data.extend_from_slice(&[0x01, 0x00]);

        // Extensions
        let sni_bytes = sni.as_bytes();
        let sni_ext_data_len = 5 + sni_bytes.len();
        let ext_len = 4 + sni_ext_data_len;

        data.extend_from_slice(&(ext_len as u16).to_be_bytes());

        // SNI Extension
        data.extend_from_slice(&[0x00, 0x00]); // SNI type
        data.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
        data.extend_from_slice(&((sni_bytes.len() + 3) as u16).to_be_bytes());
        data.push(0x00); // HostName type
        data.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        data.extend_from_slice(sni_bytes);

        // Fix record length
        let rec_len = (data.len() - 5) as u16;
        data[3..5].copy_from_slice(&rec_len.to_be_bytes());
        let hs_len = (data.len() - 9) as u32;
        data[6..9].copy_from_slice(&hs_len.to_be_bytes()[1..4]);

        data
    }

    #[test]
    fn test_sni_extraction_and_splitting() {
        let dummy = create_dummy_tls_hello("forbidden-site.org");
        let masquerader = SniSegmentationMasquerader::new(SegmentationStrategy::MidSniSplit, 10, 50);

        let extracted = masquerader.extract_sni(&dummy);
        assert!(extracted.is_some());
        let (domain, start, end) = extracted.unwrap();
        assert_eq!(domain, "forbidden-site.org");
        assert!(start < end);

        let chunks = masquerader.segment_stream(&dummy, 42);
        assert_eq!(chunks.len(), 2);
        // Reassembled bytes must match original exactly
        let reassembled: Vec<u8> = chunks.into_iter().flatten().collect();
        assert_eq!(reassembled, dummy);
    }
}
