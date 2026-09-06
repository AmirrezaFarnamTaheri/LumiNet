//! # SNI Fragmentation & Decoy Injector
//!
//! Splits TLS ClientHello records at strategic SNI boundaries or prepends
//! decoy ClientHello packets to neutralize SNI-based filtering.
//! Ported and enhanced from bypass-GFW-SNI/main.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniInjectionMode {
    SplitInMiddle,
    SplitAtSniExtension,
    DecoySniPrefix,
}

#[derive(Debug, Clone)]
pub struct SniFragmentationInjector {
    pub mode: SniInjectionMode,
    pub decoy_domain: String,
}

impl Default for SniFragmentationInjector {
    fn default() -> Self {
        Self {
            mode: SniInjectionMode::SplitInMiddle,
            decoy_domain: "www.microsoft.com".to_string(),
        }
    }
}

impl SniFragmentationInjector {
    pub fn new(mode: SniInjectionMode, decoy_domain: &str) -> Self {
        Self {
            mode,
            decoy_domain: decoy_domain.to_string(),
        }
    }

    /// Locates the Server Name Indication (SNI) string within a TLS ClientHello packet.
    pub fn extract_sni(&self, data: &[u8]) -> Option<String> {
        if data.len() < 43 || data[0] != 0x16 {
            return None; // Not a TLS Handshake record
        }

        // Search for SNI extension type 0x00, 0x00
        let mut idx = 43; // skip record header, handshake header, client version, client random
        if idx >= data.len() {
            return None;
        }

        // Skip session ID
        let sess_len = data[idx] as usize;
        idx += 1 + sess_len;
        if idx + 2 >= data.len() {
            return None;
        }

        // Skip cipher suites
        let cs_len = u16::from_be_bytes([data[idx], data[idx + 1]]) as usize;
        idx += 2 + cs_len;
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
        let ext_total_len = u16::from_be_bytes([data[idx], data[idx + 1]]) as usize;
        idx += 2;

        let end = (idx + ext_total_len).min(data.len());
        while idx + 4 <= end {
            let ext_type = u16::from_be_bytes([data[idx], data[idx + 1]]);
            let ext_len = u16::from_be_bytes([data[idx + 2], data[idx + 3]]) as usize;
            idx += 4;

            if ext_type == 0 {
                // SNI extension
                if idx + 5 <= end {
                    // Skip server_name_list length (2 bytes) and name_type (1 byte: 0 = host_name)
                    let name_len = u16::from_be_bytes([data[idx + 3], data[idx + 4]]) as usize;
                    let name_start = idx + 5;
                    if name_start + name_len <= end {
                        let name_bytes = &data[name_start..name_start + name_len];
                        return String::from_utf8(name_bytes.to_vec()).ok();
                    }
                }
            }
            idx += ext_len;
        }

        None
    }

    /// Splits a ClientHello into 2 fragments according to the injection mode.
    pub fn fragment_client_hello(&self, data: &[u8]) -> Vec<Vec<u8>> {
        if data.len() <= 5 {
            return vec![data.to_vec()];
        }

        match self.mode {
            SniInjectionMode::SplitInMiddle => {
                let mid = data.len() / 2;
                vec![data[..mid].to_vec(), data[mid..].to_vec()]
            }
            SniInjectionMode::SplitAtSniExtension => {
                // Split at 5 bytes (just after TLS record header)
                vec![data[..5].to_vec(), data[5..].to_vec()]
            }
            SniInjectionMode::DecoySniPrefix => {
                // Return decoy packet followed by real packet
                let mut decoy = Vec::with_capacity(32);
                decoy.extend_from_slice(b"\x16\x03\x01\x00\x10");
                decoy.extend_from_slice(self.decoy_domain.as_bytes());
                vec![decoy, data.to_vec()]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sni_fragmentation_split_middle() {
        let injector = SniFragmentationInjector::default();
        let client_hello = vec![0x16, 0x03, 0x01, 0x00, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05];
        let frags = injector.fragment_client_hello(&client_hello);
        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0].len() + frags[1].len(), client_hello.len());
    }

    #[test]
    fn test_sni_fragmentation_split_at_header() {
        let injector = SniFragmentationInjector::new(SniInjectionMode::SplitAtSniExtension, "example.com");
        let client_hello = vec![0x16, 0x03, 0x01, 0x00, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05];
        let frags = injector.fragment_client_hello(&client_hello);
        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0].len(), 5);
    }
}
