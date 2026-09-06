
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

pub const ANONYMIZED_DNSCRYPT_QUERY_MAGIC: [u8; 10] =
    [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00];

pub const ANONYMIZED_DNSCRYPT_OVERHEAD: usize = 16 + 2;

/// Checks if the packet starts with the anonymized DNSCrypt query magic bytes.
pub fn starts_with_relay_magic(packet: &[u8]) -> bool {
    packet.len() >= ANONYMIZED_DNSCRYPT_QUERY_MAGIC.len()
        && packet[..ANONYMIZED_DNSCRYPT_QUERY_MAGIC.len()] == ANONYMIZED_DNSCRYPT_QUERY_MAGIC
}

/// Parses an anonymized DNSCrypt query packet.
/// Extracts the target upstream resolver address and returns the inner DNSCrypt payload.
pub fn parse_anonymized_dns_query(packet: &[u8]) -> Result<(SocketAddr, &[u8]), &'static str> {
    if packet.len() < ANONYMIZED_DNSCRYPT_QUERY_MAGIC.len() + ANONYMIZED_DNSCRYPT_OVERHEAD {
        return Err("Packet too short");
    }

    if !starts_with_relay_magic(packet) {
        return Err("Missing magic prefix");
    }

    // Skip magic prefix to point to the relay data (IP + port)
    let relay_data = &packet[ANONYMIZED_DNSCRYPT_QUERY_MAGIC.len()..];

    // Read 16-byte IP address (big-endian IPv6 or IPv4-mapped IPv6)
    let mut ip_bin = [0u8; 16];
    ip_bin.copy_from_slice(&relay_data[..16]);
    let ip_v6 = Ipv6Addr::new(
        u16::from_be_bytes([ip_bin[0], ip_bin[1]]),
        u16::from_be_bytes([ip_bin[2], ip_bin[3]]),
        u16::from_be_bytes([ip_bin[4], ip_bin[5]]),
        u16::from_be_bytes([ip_bin[6], ip_bin[7]]),
        u16::from_be_bytes([ip_bin[8], ip_bin[9]]),
        u16::from_be_bytes([ip_bin[10], ip_bin[11]]),
        u16::from_be_bytes([ip_bin[12], ip_bin[13]]),
        u16::from_be_bytes([ip_bin[14], ip_bin[15]]),
    );

    // Map back to IPv4 if mapped
    let ip = match ip_v6.to_ipv4() {
        Some(ip_v4) => IpAddr::V4(ip_v4),
        None => IpAddr::V6(ip_v6),
    };

    // Read 2-byte port (big-endian u16)
    let port = u16::from_be_bytes([relay_data[16], relay_data[17]]);

    let inner_payload = &relay_data[ANONYMIZED_DNSCRYPT_OVERHEAD..];

    Ok((SocketAddr::new(ip, port), inner_payload))
}

/// Builds/encapsulates a payload into an anonymized DNSCrypt query.
pub fn build_anonymized_dns_query(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(
        ANONYMIZED_DNSCRYPT_QUERY_MAGIC.len() + ANONYMIZED_DNSCRYPT_OVERHEAD + payload.len(),
    );

    packet.extend_from_slice(&ANONYMIZED_DNSCRYPT_QUERY_MAGIC);

    // Encapsulate target IP as 16-byte IPv6 representation (Mapped IPv4 if V4)
    let ip_bytes = match target.ip() {
        IpAddr::V4(ip_v4) => ip_v4.to_ipv6_mapped().octets(),
        IpAddr::V6(ip_v6) => ip_v6.octets(),
    };
    packet.extend_from_slice(&ip_bytes);

    // Encapsulate port as 2 bytes
    packet.extend_from_slice(&target.port().to_be_bytes());

    // Append inner payload
    packet.extend_from_slice(payload);

    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anonymized_dns_roundtrip_ipv4() {
        let target_addr: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let payload = b"standard_dns_payload_here";

        let packet = build_anonymized_dns_query(target_addr, payload);
        assert!(starts_with_relay_magic(&packet));

        let (parsed_addr, parsed_payload) = parse_anonymized_dns_query(&packet).unwrap();
        assert_eq!(parsed_addr, target_addr);
        assert_eq!(parsed_payload, payload);
    }

    #[test]
    fn test_anonymized_dns_roundtrip_ipv6() {
        let target_addr: SocketAddr = "[2001:db8::1]:853".parse().unwrap();
        let payload = b"another_dns_payload";

        let packet = build_anonymized_dns_query(target_addr, payload);
        assert!(starts_with_relay_magic(&packet));

        let (parsed_addr, parsed_payload) = parse_anonymized_dns_query(&packet).unwrap();
        assert_eq!(parsed_addr, target_addr);
        assert_eq!(parsed_payload, payload);
    }
}
