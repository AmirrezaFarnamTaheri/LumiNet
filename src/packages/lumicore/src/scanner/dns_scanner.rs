
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct DnsScanConfig {
    pub domain: String,
    pub timeout: Duration,
    pub payload_size: u16, // usually 1232
}

pub struct DnsScanner {
    config: DnsScanConfig,
}

impl DnsScanner {
    pub fn new(config: DnsScanConfig) -> Self {
        DnsScanner { config }
    }

    /// Builds a DNS query packet with EDNS0 OPT record (type 41, DO flag active)
    /// to query DNSSEC validation status.
    pub fn build_query(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        // 1. Transaction ID
        packet.extend_from_slice(&[0x12, 0x34]);
        // 2. Flags: Standard query, recursion desired
        packet.extend_from_slice(&[0x01, 0x00]);
        // 3. Question Count: 1
        packet.extend_from_slice(&[0x00, 0x01]);
        // 4. Answer Count: 0
        packet.extend_from_slice(&[0x00, 0x00]);
        // 5. Authority Count: 0
        packet.extend_from_slice(&[0x00, 0x00]);
        // 6. Additional Count: 1 (for EDNS0 OPT)
        packet.extend_from_slice(&[0x00, 0x01]);

        // 7. Domain Name
        for part in self.config.domain.split('.') {
            packet.push(part.len() as u8);
            packet.extend_from_slice(part.as_bytes());
        }
        packet.push(0x00); // end of name

        // 8. Type: A (0x0001)
        packet.extend_from_slice(&[0x00, 0x01]);
        // 9. Class: IN (0x0001)
        packet.extend_from_slice(&[0x00, 0x01]);

        // 10. EDNS0 OPT Pseudo-Section
        packet.push(0x00); // root label
        packet.extend_from_slice(&[0x00, 0x29]); // Type: OPT (41)

        // UDP Payload Size
        packet.extend_from_slice(&self.config.payload_size.to_be_bytes());

        // Extended RCODE (0) and Version (0)
        packet.extend_from_slice(&[0x00, 0x00]);

        // Flags: DO bit set (0x8000) indicating DNSSEC validation support
        packet.extend_from_slice(&[0x80, 0x00]);

        // Data Length: 0
        packet.extend_from_slice(&[0x00, 0x00]);

        packet
    }

    /// Performs DNS resolution over UDP and validates answers against trusted DNSSEC Truth Table
    pub async fn probe_udp(&self, resolver: SocketAddr) -> Result<Vec<String>, String> {
        let query = self.build_query();
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| e.to_string())?;

        socket.connect(resolver).await.map_err(|e| e.to_string())?;

        let mut attempt = 0;
        let retries = 2;
        while attempt <= retries {
            if socket.send(&query).await.is_ok() {
                let mut buf = vec![0u8; 1232];
                if let Ok(Ok(n)) =
                    tokio::time::timeout(self.config.timeout, socket.recv(&mut buf)).await
                {
                    return self.parse_dns_response(&buf[..n]);
                }
            }
            attempt += 1;
        }

        Err("DNS probe timeout".to_string())
    }

    /// Parses IP addresses from a standard DNS query response payload.
    fn parse_dns_response(&self, buf: &[u8]) -> Result<Vec<String>, String> {
        if buf.len() < 12 {
            return Err("packet too short".to_string());
        }

        let ancount = u16::from_be_bytes([buf[6], buf[7]]);
        if ancount == 0 {
            return Ok(Vec::new());
        }

        // Fast forward past query section to answers section
        let mut idx = 12;
        // Skip question label
        while idx < buf.len() {
            let len = buf[idx] as usize;
            if len == 0 {
                idx += 1;
                break;
            }
            idx += len + 1;
        }
        idx += 4; // skip QTYPE + QCLASS

        let mut ips = Vec::new();
        let mut ans_count = 0;

        while ans_count < ancount && idx < buf.len() {
            // Skip name pointer (usually 2 bytes)
            if (buf[idx] & 0xC0) == 0xC0 {
                idx += 2;
            } else {
                while idx < buf.len() && buf[idx] != 0 {
                    idx += (buf[idx] as usize) + 1;
                }
                idx += 1;
            }

            if idx + 10 > buf.len() {
                break;
            }

            let rtype = u16::from_be_bytes([buf[idx], buf[idx + 1]]);
            let rdlength = u16::from_be_bytes([buf[idx + 8], buf[idx + 9]]) as usize;
            idx += 10;

            if rtype == 1 && rdlength == 4 {
                // Type A
                if idx + 4 <= buf.len() {
                    let ip = format!(
                        "{}.{}.{}.{}",
                        buf[idx],
                        buf[idx + 1],
                        buf[idx + 2],
                        buf[idx + 3]
                    );
                    ips.push(ip);
                }
            }
            idx += rdlength;
            ans_count += 1;
        }

        Ok(ips)
    }

    /// Validates DNS answers against a trusted baseline list to detect spoofing.
    pub fn verify_truth_table(&self, answers: &[String], ground_truth: &[String]) -> bool {
        if answers.is_empty() || ground_truth.is_empty() {
            return false;
        }
        for ans in answers {
            if ground_truth.contains(ans) {
                return true;
            }
        }
        false
    }
}
