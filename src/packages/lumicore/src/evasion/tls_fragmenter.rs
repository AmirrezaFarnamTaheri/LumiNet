//! TLS Record & SNI Multi-Strategy Fragmenter
//!
//! Provides 10 dynamic fragmentation techniques to prevent Deep Packet Inspection (DPI)
//! from observing contiguous Server Name Indication (SNI) hostnames in a single TCP segment.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsFragmentStrategy {
    /// FinalMask: Rewrites the ClientHello payload into two distinct valid TLS records.
    FinalMaskTlsHello { record1_payload_len: usize },
    /// Fixed-size chunks (e.g. 5, 10, 20 bytes).
    FixedChunks(usize),
    /// Splits TCP stream at the exact beginning of the SNI hostname string.
    SniBoundary,
    /// Splits TCP stream directly in the middle of the SNI hostname string.
    SniSplit,
    /// Splits ClientHello payload into two valid TLS records at half payload length.
    TlsRecordFrag,
    /// Splits ClientHello payload into two valid TLS records directly at the SNI boundary.
    TlsSniRecords,
    /// Splits byte stream exactly in half.
    Half,
    /// Raw unfragmented passthrough.
    Raw,
}

pub struct TlsFragmenter;

impl TlsFragmenter {
    /// Locates the byte range `(offset, length)` of the SNI hostname in a TLS ClientHello.
    pub fn locate_sni(data: &[u8]) -> Option<(usize, usize)> {
        // TLS record header: 5 bytes (0x16, version[2], length[2])
        if data.len() < 9 || data[0] != 0x16 {
            return None;
        }

        let record_payload_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        let record_end = (5 + record_payload_len).min(data.len());

        let mut pos = 5;
        // Handshake type must be ClientHello (0x01)
        if pos >= data.len() || data[pos] != 0x01 {
            return None;
        }

        // Handshake header: type(1) + length(3) + client_version(2) + random(32)
        pos += 1 + 3 + 2 + 32;
        if pos >= record_end {
            return None;
        }

        // Session ID length
        let session_id_len = data[pos] as usize;
        pos += 1 + session_id_len;
        if pos + 2 > record_end {
            return None;
        }

        // Cipher suites length
        let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + cipher_suites_len;
        if pos >= record_end {
            return None;
        }

        // Compression methods length
        let comp_len = data[pos] as usize;
        pos += 1 + comp_len;
        if pos + 2 > record_end {
            return None;
        }

        // Extensions length
        let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let ext_end = (pos + ext_len).min(record_end);

        // Iterate through TLS extensions looking for SNI (type 0)
        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let ext_data_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;

            if ext_type == 0 && pos + ext_data_len <= ext_end {
                // Inside server_name extension:
                // server_name_list_length (2 bytes)
                if pos + 2 > ext_end {
                    return None;
                }
                let mut name_pos = pos + 2;
                let names_end = pos + ext_data_len;

                while name_pos + 3 <= names_end {
                    let name_type = data[name_pos];
                    let name_len = u16::from_be_bytes([data[name_pos + 1], data[name_pos + 2]]) as usize;
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

    /// Extracts the SNI hostname string from a ClientHello if present.
    pub fn extract_sni(data: &[u8]) -> Option<String> {
        let (offset, len) = Self::locate_sni(data)?;
        std::str::from_utf8(&data[offset..offset + len])
            .ok()
            .map(|s| s.to_string())
    }

    /// Rewrites a TLS ClientHello into two valid TLS records (FinalMask strategy).
    pub fn rewrite_final_mask(data: &[u8], split_len: usize) -> Vec<u8> {
        if data.len() < 6 || data[0] != 0x16 || split_len == 0 {
            return data.to_vec();
        }

        let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        let record_end = 5 + record_len;

        if record_len <= split_len || record_end > data.len() {
            return data.to_vec();
        }

        let version = [data[1], data[2]];
        let payload = &data[5..record_end];

        let record1 = Self::wrap_tls_record(version, &payload[..split_len]);
        let record2 = Self::wrap_tls_record(version, &payload[split_len..]);

        let mut out = Vec::with_capacity(record1.len() + record2.len() + (data.len() - record_end));
        out.extend_from_slice(&record1);
        out.extend_from_slice(&record2);
        if record_end < data.len() {
            out.extend_from_slice(&data[record_end..]);
        }
        out
    }

    /// Helper to construct a standard TLS record wrapper: [0x16, ver0, ver1, len0, len1, payload...]
    pub fn wrap_tls_record(version: [u8; 2], payload: &[u8]) -> Vec<u8> {
        let mut rec = Vec::with_capacity(5 + payload.len());
        rec.push(0x16);
        rec.push(version[0]);
        rec.push(version[1]);
        rec.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        rec.extend_from_slice(payload);
        rec
    }

    /// Splits data into segments according to the chosen strategy.
    pub fn fragment(data: &[u8], strategy: TlsFragmentStrategy) -> Vec<Vec<u8>> {
        if data.is_empty() {
            return vec![Vec::new()];
        }

        match strategy {
            TlsFragmentStrategy::FinalMaskTlsHello { record1_payload_len } => {
                let rewritten = Self::rewrite_final_mask(data, record1_payload_len);
                // Return as two separate TCP writes if rewritten, otherwise single chunk
                if rewritten.len() > data.len() {
                    let first_len = 5 + record1_payload_len;
                    vec![rewritten[..first_len].to_vec(), rewritten[first_len..].to_vec()]
                } else {
                    vec![rewritten]
                }
            }
            TlsFragmentStrategy::FixedChunks(size) => {
                let step = size.max(1);
                data.chunks(step).map(|c| c.to_vec()).collect()
            }
            TlsFragmentStrategy::SniBoundary => {
                let split = match Self::locate_sni(data) {
                    Some((offset, _)) => offset,
                    None => data.len() / 2,
                };
                Self::split_at(data, split)
            }
            TlsFragmentStrategy::SniSplit => {
                let split = match Self::locate_sni(data) {
                    Some((offset, len)) => offset + (len / 2).max(1),
                    None => data.len() / 2,
                };
                Self::split_at(data, split)
            }
            TlsFragmentStrategy::TlsRecordFrag => {
                Self::split_tls_record(data, false)
            }
            TlsFragmentStrategy::TlsSniRecords => {
                Self::split_tls_record(data, true)
            }
            TlsFragmentStrategy::Half => {
                Self::split_at(data, data.len() / 2)
            }
            TlsFragmentStrategy::Raw => {
                vec![data.to_vec()]
            }
        }
    }

    fn split_at(data: &[u8], requested_split: usize) -> Vec<Vec<u8>> {
        if data.len() < 2 {
            return vec![data.to_vec()];
        }
        let split = requested_split.clamp(1, data.len() - 1);
        vec![data[..split].to_vec(), data[split..].to_vec()]
    }

    fn split_tls_record(data: &[u8], at_sni: bool) -> Vec<Vec<u8>> {
        if data.len() < 6 || data[0] != 0x16 {
            return vec![data.to_vec()];
        }
        let payload = &data[5..];
        if payload.len() < 2 {
            return vec![data.to_vec()];
        }

        let requested = if at_sni {
            if let Some((offset, _)) = Self::locate_sni(data) {
                if offset > 5 { offset - 5 } else { payload.len() / 2 }
            } else {
                payload.len() / 2
            }
        } else {
            payload.len() / 2
        };

        let split = requested.clamp(1, payload.len() - 1);
        let version = [data[1], data[2]];

        vec![
            Self::wrap_tls_record(version, &payload[..split]),
            Self::wrap_tls_record(version, &payload[split..]),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthesizes a valid minimal TLS 1.2 ClientHello with an SNI extension
    fn create_test_client_hello(sni: &str) -> Vec<u8> {
        let mut handshake = Vec::new();
        // ClientHello version 3.3
        handshake.extend_from_slice(&[0x03, 0x03]);
        // Random (32 bytes)
        handshake.extend_from_slice(&[0x42; 32]);
        // Session ID (empty)
        handshake.push(0x00);
        // Cipher suites (2 bytes len + 2 bytes suite)
        handshake.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        // Compression (1 byte len + null compression)
        handshake.extend_from_slice(&[0x01, 0x00]);

        // SNI extension
        let sni_bytes = sni.as_bytes();
        let mut ext_data = Vec::new();
        let server_name_list_len = (3 + sni_bytes.len()) as u16;
        ext_data.extend_from_slice(&server_name_list_len.to_be_bytes());
        ext_data.push(0x00); // HostName type
        ext_data.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        ext_data.extend_from_slice(sni_bytes);

        // Extensions block
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes()); // Type 0 (SNI)
        extensions.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&ext_data);

        handshake.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        handshake.extend_from_slice(&extensions);

        // Wrap in Handshake (0x01 ClientHello + 3 bytes len)
        let mut hs_msg = Vec::new();
        hs_msg.push(0x01);
        let hs_len = handshake.len() as u32;
        hs_msg.push(((hs_len >> 16) & 0xFF) as u8);
        hs_msg.push(((hs_len >> 8) & 0xFF) as u8);
        hs_msg.push((hs_len & 0xFF) as u8);
        hs_msg.extend_from_slice(&handshake);

        // Wrap in Record (0x16 Handshake + TLS 1.0 + 2 bytes len)
        TlsFragmenter::wrap_tls_record([0x03, 0x01], &hs_msg)
    }

    #[test]
    fn test_locate_and_extract_sni() {
        let ch = create_test_client_hello("restricted.freedom.org");
        let extracted = TlsFragmenter::extract_sni(&ch);
        assert_eq!(extracted.as_deref(), Some("restricted.freedom.org"));
    }

    #[test]
    fn test_sni_boundary_fragmentation() {
        let ch = create_test_client_hello("restricted.freedom.org");
        let frags = TlsFragmenter::fragment(&ch, TlsFragmentStrategy::SniBoundary);
        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0].len() + frags[1].len(), ch.len());

        let (sni_offset, _) = TlsFragmenter::locate_sni(&ch).unwrap();
        assert_eq!(frags[0].len(), sni_offset);
    }

    #[test]
    fn test_sni_split_fragmentation() {
        let ch = create_test_client_hello("restricted.freedom.org");
        let frags = TlsFragmenter::fragment(&ch, TlsFragmentStrategy::SniSplit);
        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0].len() + frags[1].len(), ch.len());

        let (sni_offset, len) = TlsFragmenter::locate_sni(&ch).unwrap();
        assert_eq!(frags[0].len(), sni_offset + len / 2);
    }

    #[test]
    fn test_final_mask_rewrite() {
        let ch = create_test_client_hello("restricted.freedom.org");
        let rewritten = TlsFragmenter::rewrite_final_mask(&ch, 16);
        // Should contain two records, so total length is original length + 5 (second record header)
        assert_eq!(rewritten.len(), ch.len() + 5);
        assert_eq!(rewritten[0], 0x16);
        let rec1_len = u16::from_be_bytes([rewritten[3], rewritten[4]]) as usize;
        assert_eq!(rec1_len, 16);
        assert_eq!(rewritten[5 + 16], 0x16); // Second record header
    }

    #[test]
    fn test_fixed_chunks() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let chunks = TlsFragmenter::fragment(&data, TlsFragmentStrategy::FixedChunks(4));
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0], vec![1, 2, 3, 4]);
        assert_eq!(chunks[1], vec![5, 6, 7, 8]);
        assert_eq!(chunks[2], vec![9, 10]);
    }
}
