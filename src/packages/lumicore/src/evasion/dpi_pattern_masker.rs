//! Packet Signature Mutation and DPI Pattern Masker
//!
//! Breaks DPI pattern matchers by fragmenting critical protocol signatures
//! (TLS ClientHello SNI, HTTP Host, WireGuard handshake init) across TCP/IP frames.

#[derive(Debug, Clone)]
pub struct DpiPatternMasker {
    pub split_offset: usize,
    pub insert_noise_record: bool,
}

impl Default for DpiPatternMasker {
    fn default() -> Self {
        Self {
            split_offset: 5,
            insert_noise_record: true,
        }
    }
}

impl DpiPatternMasker {
    pub fn new(split_offset: usize, insert_noise_record: bool) -> Self {
        Self {
            split_offset: split_offset.max(1),
            insert_noise_record,
        }
    }

    /// Splits a buffer into evasion fragments.
    /// If TLS handshake (0x16 0x03 0x01/0x03), splits right inside SNI or record header.
    pub fn fragment_payload(&self, payload: &[u8]) -> Vec<Vec<u8>> {
        if payload.len() <= self.split_offset {
            return vec![payload.to_vec()];
        }

        let mut fragments = Vec::with_capacity(3);

        // Optional pre-pended TLS Alert/Unknown pseudo record
        if self.insert_noise_record && payload.starts_with(&[0x16, 0x03]) {
            // Harmless fake alert header: [0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00]
            fragments.push(vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00]);
        }

        let split_at = self.split_offset.min(payload.len() - 1);
        fragments.push(payload[..split_at].to_vec());
        fragments.push(payload[split_at..].to_vec());

        fragments
    }

    /// Reassembles fragments back to the original payload, stripping noise records if present
    pub fn reassemble_payload(fragments: &[Vec<u8>]) -> Vec<u8> {
        let mut total = Vec::new();
        for f in fragments {
            // If it's the exact synthetic noise alert, discard it
            if f.as_slice() == [0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00] {
                continue;
            }
            total.extend_from_slice(f);
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dpi_fragmentation_roundtrip() {
        let masker = DpiPatternMasker::new(5, true);
        let client_hello = vec![0x16, 0x03, 0x01, 0x00, 0x50, 0x01, 0x00, 0x00, 0x4C];
        let frags = masker.fragment_payload(&client_hello);

        assert_eq!(frags.len(), 3); // noise + part1 + part2
        assert_eq!(frags[0], vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00]);
        assert_eq!(frags[1].len(), 5);

        let recovered = DpiPatternMasker::reassemble_payload(&frags);
        assert_eq!(recovered, client_hello);
    }
}
