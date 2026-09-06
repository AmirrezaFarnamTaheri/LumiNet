//! High-throughput concurrent UDP DNS resolver scanner and response validator.
//!
//! Provides zero-allocation DNS wire query building, RFC 1035 response parsing with
//! label compression pointer traversal, expected IPv4 answer validation, and input
//! normalizers for tagged resolver entries.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

/// Builds an RFC 1035 DNS query for an IPv4 (A) record with the given transaction ID.
pub fn build_dns_a_query(domain: &str, txid: u16) -> Result<Vec<u8>, String> {
    let clean_domain = domain.trim().trim_end_matches('.');
    if clean_domain.is_empty() {
        return Err("Domain cannot be empty".to_string());
    }

    let mut packet = Vec::with_capacity(64);

    // 1. Transaction ID (2 bytes)
    packet.extend_from_slice(&txid.to_be_bytes());
    // 2. Flags (Standard query with recursion desired: 0x0100)
    packet.extend_from_slice(&[0x01, 0x00]);
    // 3. QDCOUNT (Questions: 1)
    packet.extend_from_slice(&[0x00, 0x01]);
    // 4. ANCOUNT (Answers: 0)
    packet.extend_from_slice(&[0x00, 0x00]);
    // 5. NSCOUNT (Authority: 0)
    packet.extend_from_slice(&[0x00, 0x00]);
    // 6. ARCOUNT (Additional: 0)
    packet.extend_from_slice(&[0x00, 0x00]);

    // 7. QNAME (Length-prefixed labels)
    for label in clean_domain.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return Err(format!("Invalid DNS label length: {}", label));
        }
        packet.push(bytes.len() as u8);
        packet.extend_from_slice(bytes);
    }
    packet.push(0x00); // Root label null terminator

    // 8. QTYPE (Type A = 1)
    packet.extend_from_slice(&[0x00, 0x01]);
    // 9. QCLASS (Class IN = 1)
    packet.extend_from_slice(&[0x00, 0x01]);

    Ok(packet)
}

/// Skips an RFC 1035 domain name at offset, handling both length-prefixed labels and compression pointers.
/// Returns the new offset immediately following the domain name representation.
pub fn skip_dns_name(data: &[u8], mut offset: usize) -> Option<usize> {
    while offset < data.len() {
        let length = data[offset];
        if (length & 0xC0) == 0xC0 {
            // Compression pointer is 2 bytes
            return Some(offset + 2);
        }
        if length == 0 {
            // Null terminator for uncompressed label sequence
            return Some(offset + 1);
        }
        offset += 1 + (length as usize);
    }
    None
}

/// Validates whether data is a valid DNS response matching 	xid and optionally verifying
/// that at least one returned A record matches xpected_ip.
pub fn is_valid_dns_response(data: &[u8], txid: u16, expected_ip: Option<Ipv4Addr>) -> bool {
    if data.len() < 12 {
        return false;
    }

    // 1. Check Transaction ID
    let resp_txid = u16::from_be_bytes([data[0], data[1]]);
    if resp_txid != txid {
        return false;
    }

    // 2. Check Flags: QR=1 (response), RCODE=0 (NoError)
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qr = (flags >> 15) & 0x01;
    let rcode = flags & 0x0F;
    let ancount = u16::from_be_bytes([data[6], data[7]]);

    if qr != 1 || rcode != 0 || ancount == 0 {
        return false;
    }

    // 3. Skip Questions
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let mut offset = 12usize;
    for _ in 0..qdcount {
        offset = match skip_dns_name(data, offset) {
            Some(o) => o,
            None => return false,
        };
        offset += 4; // Skip QTYPE (2) + QCLASS (2)
        if offset > data.len() {
            return false;
        }
    }

    // 4. Parse Answers
    let expected_octets = expected_ip.map(|ip| ip.octets());
    for _ in 0..ancount {
        if offset >= data.len() {
            break;
        }
        offset = match skip_dns_name(data, offset) {
            Some(o) => o,
            None => return false,
        };
        if offset + 10 > data.len() {
            return false;
        }

        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        // skip TTL: data[offset + 4..offset + 8]
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > data.len() {
            return false;
        }

        // Check Type A (1), Class IN (1), length 4
        if rtype == 1 && rclass == 1 && rdlength == 4 {
            let ip_bytes = [
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ];
            match expected_octets {
                None => return true,
                Some(exp) if exp == ip_bytes => return true,
                _ => {}
            }
        }
        offset += rdlength;
    }

    false
}

/// Normalizes and parses raw resolver inputs into valid SocketAddr candidate endpoints.
/// Supports bracketed tags [Country-Tag] 1.2.3.4:53, raw IPs 8.8.8.8, and custom port defaults.
pub fn parse_resolver_entry(raw: &str, default_ports: &[u16]) -> Option<Vec<SocketAddr>> {
    let mut line = raw.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    // Strip bracketed tag prefix: e.g. "[IR-MCI] 10.20.30.40"
    if line.starts_with('[') {
        if let Some(idx) = line.find(']') {
            line = line[idx + 1..].trim();
        }
    }

    let mut host = line;
    let mut explicit_port: Option<u16> = None;

    if let Some(idx) = line.rfind(':') {
        let host_part = &line[..idx].trim();
        let port_part = &line[idx + 1..].trim();
        if !host_part.is_empty() {
            if let Ok(p) = port_part.parse::<u16>() {
                if p > 0 {
                    host = host_part;
                    explicit_port = Some(p);
                }
            }
        }
    }

    let ip: Ipv4Addr = host.parse().ok()?;
    let ports = match explicit_port {
        Some(p) => vec![p],
        None => {
            if default_ports.is_empty() {
                vec![53]
            } else {
                default_ports.to_vec()
            }
        }
    };

    let addrs = ports
        .into_iter()
        .map(|p| SocketAddr::V4(SocketAddrV4::new(ip, p)))
        .collect();

    Some(addrs)
}
