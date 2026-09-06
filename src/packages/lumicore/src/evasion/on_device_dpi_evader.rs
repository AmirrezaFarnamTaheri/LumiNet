// Pure Rust implementation: On-Device DPI Evasion Engine

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvasionTechnique {
    SniSplit { split_offset: usize },
    HttpHeaderDesync,
    OutOfOrderInterleave { chunk_size: usize },
    DecoyTtlPadding { decoy_ttl: u8 },
}

#[derive(Debug, Clone)]
pub struct DpiEvasionProfile {
    pub techniques: Vec<EvasionTechnique>,
    pub min_packet_size: usize,
}

impl Default for DpiEvasionProfile {
    fn default() -> Self {
        Self {
            techniques: vec![
                EvasionTechnique::SniSplit { split_offset: 2 },
                EvasionTechnique::HttpHeaderDesync,
            ],
            min_packet_size: 16,
        }
    }
}

pub struct OnDeviceDpiEvader {
    pub profile: DpiEvasionProfile,
    pub evaded_packets_count: u64,
}

impl OnDeviceDpiEvader {
    pub fn new(profile: DpiEvasionProfile) -> Self {
        Self {
            profile,
            evaded_packets_count: 0,
        }
    }

    pub fn apply_sni_split<'a>(&mut self, client_hello: &'a [u8], split_offset: usize) -> Vec<Vec<u8>> {
        self.evaded_packets_count += 1;
        // Verify TLS Handshake: 0x16 0x03
        if client_hello.len() < 5 || client_hello[0] != 0x16 {
            return vec![client_hello.to_vec()];
        }

        let split_pos = split_offset.clamp(1, client_hello.len() - 1);
        vec![
            client_hello[..split_pos].to_vec(),
            client_hello[split_pos..].to_vec(),
        ]
    }

    pub fn apply_http_header_desync(&mut self, request: &[u8]) -> Vec<u8> {
        self.evaded_packets_count += 1;
        if let Ok(req_str) = std::str::from_utf8(request) {
            let mut desynced = String::new();
            for line in req_str.lines() {
                if line.to_ascii_lowercase().starts_with("host:") {
                    // Inject whitespace desync trick: "Host:  example.com" or "hOst: example.com"
                    let parts: Vec<&str> = line.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        desynced.push_str(&format!("hOst: {}\r\n", parts[1].trim()));
                        continue;
                    }
                }
                desynced.push_str(line);
                desynced.push_str("\r\n");
            }
            desynced.into_bytes()
        } else {
            request.to_vec()
        }
    }

    pub fn generate_out_of_order_chunks(&mut self, data: &[u8], chunk_size: usize) -> Vec<(u32, Vec<u8>)> {
        self.evaded_packets_count += 1;
        let mut chunks = Vec::new();
        let mut offset = 0u32;

        for slice in data.chunks(chunk_size.max(1)) {
            chunks.push((offset, slice.to_vec()));
            offset += slice.len() as u32;
        }

        // Interleave / reverse order for transmission simulation
        if chunks.len() > 1 {
            chunks.swap(0, 1);
        }
        chunks
    }

    pub fn craft_ttl_decoy_pair(&mut self, real_payload: &[u8], decoy_ttl: u8) -> ((u8, Vec<u8>), (u8, Vec<u8>)) {
        self.evaded_packets_count += 1;
        // Decoy packet with intentionally low TTL (e.g. 2 hops) containing randomized noise
        let mut decoy_payload = real_payload.to_vec();
        for b in decoy_payload.iter_mut() {
            *b ^= 0x55;
        }

        let decoy = (decoy_ttl, decoy_payload);
        let real = (64u8, real_payload.to_vec());
        (decoy, real)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sni_fragmentation() {
        let mut evader = OnDeviceDpiEvader::new(DpiEvasionProfile::default());
        let tls_hello = vec![0x16, 0x03, 0x01, 0x00, 0x20, 0x01, 0x02, 0x03, 0x04];
        let fragments = evader.apply_sni_split(&tls_hello, 3);
        assert_eq!(fragments.len(), 2);
        assert_eq!(fragments[0], vec![0x16, 0x03, 0x01]);
        assert_eq!(fragments[1], vec![0x00, 0x20, 0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_http_header_desync() {
        let mut evader = OnDeviceDpiEvader::new(DpiEvasionProfile::default());
        let http_raw = b"GET / HTTP/1.1\r\nHost: blocked-site.com\r\nUser-Agent: curl\r\n\r\n";
        let desynced = evader.apply_http_header_desync(http_raw);
        let desynced_str = std::str::from_utf8(&desynced).unwrap();
        assert!(desynced_str.contains("hOst: blocked-site.com"));
    }

    #[test]
    fn test_out_of_order_and_decoy() {
        let mut evader = OnDeviceDpiEvader::new(DpiEvasionProfile::default());
        let data = b"ABCDEFGHIJKL";
        let chunks = evader.generate_out_of_order_chunks(data, 4);
        assert_eq!(chunks.len(), 3);
        // Chunks swapped: first chunk sent has offset 4
        assert_eq!(chunks[0].0, 4);

        let (decoy, real) = evader.craft_ttl_decoy_pair(b"HELLO", 3);
        assert_eq!(decoy.0, 3);
        assert_eq!(real.0, 64);
        assert_ne!(decoy.1, real.1);
    }
}
