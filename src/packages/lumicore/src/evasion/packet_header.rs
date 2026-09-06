//! # Raw TCP/IP Packet Header Manipulation
//!
//! Raw IP/TCP packet headers manipulation, sequence number offset calculations,
//! and RFC 1071 internet checksum computations.

/// Computes the standard RFC 1071 internet checksum.
pub fn checksum_data(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i < data.len() - 1 {
        let word = ((data[i] as u32) << 8) | (data[i + 1] as u32);
        sum += word;
        i += 2;
    }
    if data.len() % 2 == 1 {
        sum += (data[data.len() - 1] as u32) << 8;
    }
    while sum > 0xFFFF {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    !sum as u16
}

/// Returns the IPv4 header length in bytes.
pub fn get_ip_header_len(raw: &[u8]) -> usize {
    if raw.is_empty() {
        return 0;
    }
    (raw[0] & 0x0F) as usize * 4
}

/// Returns the TCP header length in bytes.
pub fn get_tcp_header_len(raw: &[u8]) -> usize {
    let ip_len = get_ip_header_len(raw);
    if raw.len() < ip_len + 20 {
        return 0;
    }
    ((raw[ip_len + 12] >> 4) as usize) * 4
}

/// Calculates and sets the IPv4 header checksum at offset 10-11.
pub fn compute_ip_checksum(raw: &mut [u8]) {
    let ip_len = get_ip_header_len(raw);
    if raw.len() < ip_len || ip_len < 20 {
        return;
    }
    // Zero out existing checksum
    raw[10] = 0;
    raw[11] = 0;
    let sum = checksum_data(&raw[..ip_len]);
    raw[10] = (sum >> 8) as u8;
    raw[11] = (sum & 0xFF) as u8;
}

/// Calculates and sets the TCP checksum using the IPv4 pseudo-header.
pub fn compute_tcp_checksum(raw: &mut [u8]) {
    let ip_len = get_ip_header_len(raw);
    if raw.len() < ip_len + 20 {
        return;
    }

    // Copy IP addresses to break borrowing reference to raw
    let mut src_ip = [0u8; 4];
    src_ip.copy_from_slice(&raw[12..16]);
    let mut dst_ip = [0u8; 4];
    dst_ip.copy_from_slice(&raw[16..20]);

    let tcp_len = raw.len() - ip_len;

    // Zero out existing TCP checksum (at offset 16-17 of TCP header)
    let tcp_offset = ip_len;
    raw[tcp_offset + 16] = 0;
    raw[tcp_offset + 17] = 0;

    // Build pseudo-header: src_ip(4) + dst_ip(4) + zero(1) + protocol(1) + tcp_len(2)
    let mut pseudo = vec![0u8; 12];
    pseudo[0..4].copy_from_slice(&src_ip);
    pseudo[4..8].copy_from_slice(&dst_ip);
    pseudo[8] = 0;
    pseudo[9] = 6; // TCP Protocol
    pseudo[10] = (tcp_len >> 8) as u8;
    pseudo[11] = (tcp_len & 0xFF) as u8;

    let mut data = Vec::with_capacity(pseudo.len() + tcp_len);
    data.extend_from_slice(&pseudo);
    data.extend_from_slice(&raw[ip_len..]);

    let sum = checksum_data(&data);
    raw[tcp_offset + 16] = (sum >> 8) as u8;
    raw[tcp_offset + 17] = (sum & 0xFF) as u8;
}

/// Gets the 32-bit TCP sequence number.
pub fn get_tcp_seq(raw: &[u8]) -> u32 {
    let ip_len = get_ip_header_len(raw);
    let off = ip_len + 4;
    if raw.len() < off + 4 {
        return 0;
    }
    u32::from_be_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]])
}

/// Sets the 32-bit TCP sequence number.
pub fn set_tcp_seq(raw: &mut [u8], seq: u32) {
    let ip_len = get_ip_header_len(raw);
    let off = ip_len + 4;
    if raw.len() < off + 4 {
        return;
    }
    let bytes = seq.to_be_bytes();
    raw[off..off + 4].copy_from_slice(&bytes);
}

/// Gets the 32-bit TCP acknowledgement number.
pub fn get_tcp_ack(raw: &[u8]) -> u32 {
    let ip_len = get_ip_header_len(raw);
    let off = ip_len + 8;
    if raw.len() < off + 4 {
        return 0;
    }
    u32::from_be_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]])
}

/// Sets the 32-bit TCP acknowledgement number.
pub fn set_tcp_ack(raw: &mut [u8], ack: u32) {
    let ip_len = get_ip_header_len(raw);
    let off = ip_len + 8;
    if raw.len() < off + 4 {
        return;
    }
    let bytes = ack.to_be_bytes();
    raw[off..off + 4].copy_from_slice(&bytes);
}

/// Swaps the payload of a TCP packet, adjusts IP total length, and returns the new packet.
pub fn set_tcp_payload(raw: &[u8], payload: &[u8]) -> Vec<u8> {
    let ip_len = get_ip_header_len(raw);
    let tcp_hdr_len = get_tcp_header_len(raw);
    let headers_len = ip_len + tcp_hdr_len;

    if raw.len() < headers_len {
        return raw.to_vec();
    }

    let mut new_pkt = vec![0u8; headers_len + payload.len()];
    new_pkt[..headers_len].copy_from_slice(&raw[..headers_len]);
    new_pkt[headers_len..].copy_from_slice(payload);

    // Update IP Total Length
    let total_len = new_pkt.len() as u16;
    new_pkt[2] = (total_len >> 8) as u8;
    new_pkt[3] = (total_len & 0xFF) as u8;

    new_pkt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_data() {
        let data = [
            0x45, 0x00, 0x00, 0x28, 0x1a, 0x2b, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x7f, 0x00,
            0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
        ];
        let sum = checksum_data(&data);
        assert_ne!(sum, 0);
    }

    #[test]
    fn test_ip_header_len() {
        let data = [0x45, 0x00, 0x00, 0x28];
        assert_eq!(get_ip_header_len(&data), 20);
    }
}
