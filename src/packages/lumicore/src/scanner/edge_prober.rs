
use std::net::Ipv4Addr;

pub struct EdgeProber {
    target_ip: Ipv4Addr,
    target_port: u16,
}

impl EdgeProber {
    pub fn new(target_ip: Ipv4Addr, target_port: u16) -> Self {
        EdgeProber {
            target_ip,
            target_port,
        }
    }

    /// Scans a TLS ClientHello record to find the byte offset where the SNI extension is located.
    /// Returns the start index of the SNI domain name string.
    pub fn find_sni_offset(&self, payload: &[u8]) -> Option<usize> {
        if payload.len() < 5 || payload[0] != 0x16 {
            return None; // Not a TLS Handshake record
        }

        let mut idx = 43; // Skip TLS Record Header + Handshake Header + ClientRandom + SessionID

        // Skip Session ID payload
        if idx >= payload.len() {
            return None;
        }
        let session_id_len = payload[idx] as usize;
        idx += 1 + session_id_len;

        // Skip Cipher Suites
        if idx + 2 > payload.len() {
            return None;
        }
        let cipher_suites_len = u16::from_be_bytes([payload[idx], payload[idx + 1]]) as usize;
        idx += 2 + cipher_suites_len;

        // Skip Compression Methods
        if idx >= payload.len() {
            return None;
        }
        let compression_len = payload[idx] as usize;
        idx += 1 + compression_len;

        // Extensions
        if idx + 2 > payload.len() {
            return None;
        }
        let ext_end = idx + 2 + (u16::from_be_bytes([payload[idx], payload[idx + 1]]) as usize);
        idx += 2;

        while idx + 4 <= ext_end && idx < payload.len() {
            let ext_type = u16::from_be_bytes([payload[idx], payload[idx + 1]]);
            let ext_len = u16::from_be_bytes([payload[idx + 2], payload[idx + 3]]) as usize;
            idx += 4;

            if ext_type == 0 {
                // SNI Extension type
                if idx + 5 <= payload.len() {
                    // Skip Name List Length (2 bytes) + Name Type (1 byte) + Name Length (2 bytes)
                    let name_len =
                        u16::from_be_bytes([payload[idx + 3], payload[idx + 4]]) as usize;
                    if idx + 5 + name_len <= payload.len() {
                        return Some(idx + 5);
                    }
                }
            }
            idx += ext_len;
        }

        None
    }

    /// Splits ClientHello payload at the SNI boundary, creating two fragments.
    pub fn fragment_sni(&self, payload: &[u8], sni_offset: usize) -> (Vec<u8>, Vec<u8>) {
        if sni_offset >= payload.len() {
            return (payload.to_vec(), Vec::new());
        }
        let (f1, f2) = payload.split_at(sni_offset);
        (f1.to_vec(), f2.to_vec())
    }

    /// Crafts a raw TCP segment with an out-of-order sequence number to confuse DPI middleboxes.
    /// The sequence number is calculated by subtracting 100,000.
    pub fn craft_desync_tcp(
        &self,
        src_ip: Ipv4Addr,
        src_port: u16,
        seq_num: u32,
        ack_num: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let decoy_seq = seq_num.wrapping_sub(100_000); // Subtract 100k to bypass sequence tracking
        let total_len = 20 + 20 + payload.len();

        let mut pkt = Vec::with_capacity(total_len);

        // IPv4 Header
        pkt.push(0x45); // Version/IHL
        pkt.push(0x00); // TOS
        pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
        pkt.extend_from_slice(&[0xaa, 0xbb]); // Identification
        pkt.extend_from_slice(&[0x40, 0x00]); // Flags: DF
        pkt.push(0x40); // TTL
        pkt.push(0x06); // Protocol: TCP
        pkt.extend_from_slice(&[0x00, 0x00]); // Header Checksum
        pkt.extend_from_slice(&src_ip.octets());
        pkt.extend_from_slice(&self.target_ip.octets());

        // TCP Header
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&self.target_port.to_be_bytes());
        pkt.extend_from_slice(&decoy_seq.to_be_bytes());
        pkt.extend_from_slice(&ack_num.to_be_bytes());
        pkt.push(0x50); // Data Offset
        pkt.push(0x18); // Flags: ACK, PSH
        pkt.extend_from_slice(&[0xfa, 0xf0]); // Window
        pkt.extend_from_slice(&[0x00, 0x00]); // Checksum
        pkt.extend_from_slice(&[0x00, 0x00]); // Urgent Pointer

        // Payload
        pkt.extend_from_slice(payload);

        // Compute Checksums
        Self::fill_checksums(&mut pkt);

        pkt
    }

    fn fill_checksums(pkt: &mut [u8]) {
        // IP checksum
        let mut sum = 0u32;
        for i in (0..20).step_by(2) {
            sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
        }
        while (sum >> 16) > 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let ip_csum = !(sum as u16);
        pkt[10] = (ip_csum >> 8) as u8;
        pkt[11] = (ip_csum & 0xff) as u8;

        // TCP checksum (with pseudo-header)
        let tcp_len = (pkt.len() - 20) as u32;
        let mut sum = 0u32;

        // Pseudo-header IP addresses
        for i in (12..20).step_by(2) {
            sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
        }
        sum += 6; // Protocol = 6
        sum += tcp_len;

        // TCP Header + Payload
        for i in (20..pkt.len() - 1).step_by(2) {
            sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
        }
        if !pkt.len().is_multiple_of(2) {
            sum += (pkt[pkt.len() - 1] as u32) << 8;
        }

        while (sum >> 16) > 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let tcp_csum = !(sum as u16);
        pkt[36] = (tcp_csum >> 8) as u8;
        pkt[37] = (tcp_csum & 0xff) as u8;
    }
}
