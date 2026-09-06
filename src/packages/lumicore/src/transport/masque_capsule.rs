//! # MASQUE Capsule Protocol (RFC 9297) & CONNECT-IP Engine
//!
//! Implements HTTP Datagrams and Capsule protocol framing for MASQUE proxying,
//! including streaming capsule parsing, address assignments, route advertisements,
//! datagram encapsulation with context IDs, and tunnel readiness verification probes.

use std::net::Ipv4Addr;
use thiserror::Error;

pub const CAPSULE_DATAGRAM: u64 = 0x00;
pub const CAPSULE_ADDRESS_ASSIGN: u64 = 0x01;
pub const CAPSULE_ADDRESS_REQUEST: u64 = 0x02;
pub const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 0x03;

pub const CONNECT_IP_CONTEXT_ID: u64 = 0x00;
pub const MAX_CAPSULE_BUF: usize = 256 * 1024;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum MasqueError {
    #[error("buffer underflow parsing varint or capsule")]
    Underflow,
    #[error("invalid IP version: {0}")]
    InvalidIpVersion(u8),
    #[error("capsule buffer limit exceeded")]
    BufferLimitExceeded,
    #[error("stream ID or context ID mismatch")]
    Mismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignedAddress {
    pub request_id: u64,
    pub ip_version: u8,
    pub address: Vec<u8>,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAdvertisement {
    pub ip_version: u8,
    pub start: Vec<u8>,
    pub end: Vec<u8>,
    pub protocol: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capsule {
    AddressAssign(Vec<AssignedAddress>),
    AddressRequest {
        request_id: u64,
        ip_version: u8,
        prefix_len: u8,
    },
    Datagram(Vec<u8>),
    RouteAdvertisement(Vec<RouteAdvertisement>),
    Unknown {
        kind: u64,
        payload: Vec<u8>,
    },
}

// ============================================================================
// RFC 9000 Variable-Length Integer Encoding / Decoding
// ============================================================================

pub fn varint_len(v: u64) -> usize {
    if v < 64 {
        1
    } else if v < 16_384 {
        2
    } else if v < 1_073_741_824 {
        4
    } else {
        8
    }
}

pub fn encode_varint(val: u64, out: &mut Vec<u8>) {
    if val < 64 {
        out.push(val as u8);
    } else if val < 16_384 {
        let v = (val as u16) | 0x4000;
        out.extend_from_slice(&v.to_be_bytes());
    } else if val < 1_073_741_824 {
        let v = (val as u32) | 0x8000_0000;
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        let v = val | 0xc000_0000_0000_0000;
        out.extend_from_slice(&v.to_be_bytes());
    }
}

pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let tag = first >> 6;
    match tag {
        0b00 => Some((first as u64, 1)),
        0b01 => {
            if buf.len() < 2 {
                return None;
            }
            let bytes = [buf[0] & 0x3f, buf[1]];
            Some((u16::from_be_bytes(bytes) as u64, 2))
        }
        0b10 => {
            if buf.len() < 4 {
                return None;
            }
            let bytes = [buf[0] & 0x3f, buf[1], buf[2], buf[3]];
            Some((u32::from_be_bytes(bytes) as u64, 4))
        }
        0b11 => {
            if buf.len() < 8 {
                return None;
            }
            let bytes = [
                buf[0] & 0x3f,
                buf[1],
                buf[2],
                buf[3],
                buf[4],
                buf[5],
                buf[6],
                buf[7],
            ];
            Some((u64::from_be_bytes(bytes), 8))
        }
        _ => unreachable!(),
    }
}

// ============================================================================
// Capsule Construction & Serialization
// ============================================================================

#[inline]
pub fn quarter_stream_id(stream_id: u64) -> u64 {
    stream_id / 4
}

/// Encodes an IP packet into an RFC 9297 HTTP/3 Datagram payload.
pub fn encode_ip_datagram(stream_id: u64, ip_packet: &[u8]) -> Vec<u8> {
    let qsid = quarter_stream_id(stream_id);
    let ctx = CONNECT_IP_CONTEXT_ID;

    let mut out = Vec::with_capacity(varint_len(qsid) + varint_len(ctx) + ip_packet.len());
    encode_varint(qsid, &mut out);
    encode_varint(ctx, &mut out);
    out.extend_from_slice(ip_packet);
    out
}

/// Decodes an RFC 9297 HTTP/3 Datagram payload, validating quarter-stream ID and context ID.
pub fn decode_ip_datagram(datagram: &[u8], expect_stream_id: u64) -> Result<Option<Vec<u8>>, MasqueError> {
    let (qsid, n1) = decode_varint(datagram).ok_or(MasqueError::Underflow)?;
    if qsid != quarter_stream_id(expect_stream_id) {
        return Ok(None);
    }

    let (ctx, n2) = decode_varint(&datagram[n1..]).ok_or(MasqueError::Underflow)?;
    if ctx != CONNECT_IP_CONTEXT_ID {
        return Ok(None);
    }

    let rest = &datagram[n1 + n2..];
    Ok(Some(rest.to_vec()))
}

/// Encodes a generic RFC 9297 capsule.
pub fn encode_capsule(kind: u64, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(varint_len(kind) + varint_len(value.len() as u64) + value.len());
    encode_varint(kind, &mut out);
    encode_varint(value.len() as u64, &mut out);
    out.extend_from_slice(value);
    out
}

/// Encodes an RFC 9297 ADDRESS_REQUEST capsule.
pub fn encode_address_request(request_id: u64, ip_version: u8, prefix_len: u8) -> Vec<u8> {
    let mut value = Vec::with_capacity(varint_len(request_id) + 2);
    encode_varint(request_id, &mut value);
    value.push(ip_version);
    value.push(prefix_len);
    encode_capsule(CAPSULE_ADDRESS_REQUEST, &value)
}

/// Encodes an RFC 9297 DATAGRAM capsule for HTTP/2 fallback.
pub fn encode_datagram_capsule(ip_packet: &[u8]) -> Vec<u8> {
    encode_capsule(CAPSULE_DATAGRAM, ip_packet)
}

/// Checks if buffer begins with a valid IPv4 or IPv6 header.
pub fn looks_like_ip_packet(data: &[u8]) -> bool {
    match data.first() {
        Some(&first) => {
            let ver = first >> 4;
            (ver == 4 || ver == 6) && data.len() >= 20
        }
        None => false,
    }
}

/// Extracts inner IP packet, handling optional context ID prefix.
pub fn strip_datagram_context(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.is_empty() {
        return None;
    }

    if let Some((ctx, consumed)) = decode_varint(payload) {
        if ctx == CONNECT_IP_CONTEXT_ID {
            let inner = &payload[consumed..];
            if looks_like_ip_packet(inner) {
                return Some(inner.to_vec());
            }
        }
    }

    if looks_like_ip_packet(payload) {
        return Some(payload.to_vec());
    }

    None
}

// ============================================================================
// Streaming Capsule Parser
// ============================================================================

#[derive(Debug, Default)]
pub struct CapsuleParser {
    buf: Vec<u8>,
}

impl CapsuleParser {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn push(&mut self, data: &[u8]) {
        if self.buf.len().saturating_add(data.len()) > MAX_CAPSULE_BUF {
            tracing::warn!("CapsuleParser buffer exceeded {} bytes, resetting", MAX_CAPSULE_BUF);
            self.buf.clear();
            return;
        }
        self.buf.extend_from_slice(data);
    }

    pub fn next(&mut self) -> Result<Option<Capsule>, MasqueError> {
        let (kind, n1) = match decode_varint(&self.buf) {
            Some(v) => v,
            None => return Ok(None),
        };

        let (len, n2) = match decode_varint(&self.buf[n1..]) {
            Some(v) => v,
            None => return Ok(None),
        };

        let len = len as usize;
        let header_len = n1 + n2;
        if self.buf.len() < header_len + len {
            return Ok(None);
        }

        let value = self.buf[header_len..header_len + len].to_vec();
        self.buf.drain(0..header_len + len);

        let capsule = match kind {
            CAPSULE_ADDRESS_ASSIGN => Capsule::AddressAssign(parse_address_assign(&value)?),
            CAPSULE_ADDRESS_REQUEST => parse_address_request(&value)?,
            CAPSULE_ROUTE_ADVERTISEMENT => {
                Capsule::RouteAdvertisement(parse_route_advertisement(&value)?)
            }
            CAPSULE_DATAGRAM => Capsule::Datagram(value),
            other => Capsule::Unknown {
                kind: other,
                payload: value,
            },
        };

        Ok(Some(capsule))
    }
}

fn parse_address_assign(value: &[u8]) -> Result<Vec<AssignedAddress>, MasqueError> {
    let mut out = Vec::new();
    let mut cursor = 0;

    while cursor < value.len() {
        let (request_id, n) = decode_varint(&value[cursor..]).ok_or(MasqueError::Underflow)?;
        cursor += n;

        if cursor >= value.len() {
            return Err(MasqueError::Underflow);
        }
        let ip_version = value[cursor];
        cursor += 1;

        let addr_len = match ip_version {
            4 => 4,
            6 => 16,
            other => return Err(MasqueError::InvalidIpVersion(other)),
        };

        if cursor + addr_len >= value.len() {
            return Err(MasqueError::Underflow);
        }
        let address = value[cursor..cursor + addr_len].to_vec();
        cursor += addr_len;

        let prefix_len = value[cursor];
        cursor += 1;

        out.push(AssignedAddress {
            request_id,
            ip_version,
            address,
            prefix_len,
        });
    }

    Ok(out)
}

fn parse_address_request(value: &[u8]) -> Result<Capsule, MasqueError> {
    let mut cursor = 0;
    let (request_id, n) = decode_varint(value).ok_or(MasqueError::Underflow)?;
    cursor += n;

    if cursor + 2 > value.len() {
        return Err(MasqueError::Underflow);
    }
    let ip_version = value[cursor];
    let prefix_len = value[cursor + 1];

    Ok(Capsule::AddressRequest {
        request_id,
        ip_version,
        prefix_len,
    })
}

fn parse_route_advertisement(value: &[u8]) -> Result<Vec<RouteAdvertisement>, MasqueError> {
    let mut out = Vec::new();
    let mut cursor = 0;

    while cursor < value.len() {
        if cursor >= value.len() {
            break;
        }
        let ip_version = value[cursor];
        cursor += 1;

        let addr_len = match ip_version {
            4 => 4,
            6 => 16,
            other => return Err(MasqueError::InvalidIpVersion(other)),
        };

        if cursor + addr_len * 2 + 1 > value.len() {
            return Err(MasqueError::Underflow);
        }

        let start = value[cursor..cursor + addr_len].to_vec();
        cursor += addr_len;

        let end = value[cursor..cursor + addr_len].to_vec();
        cursor += addr_len;

        let protocol = value[cursor];
        cursor += 1;

        out.push(RouteAdvertisement {
            ip_version,
            start,
            end,
            protocol,
        });
    }

    Ok(out)
}

// ============================================================================
// DNS Probe Verification Generator (Active Tunnel Prober)
// ============================================================================

/// Builds a real DNS A-record query probe packet inside a syntactically valid IPv4/UDP frame
/// targeted to 8.8.8.8:53, used to verify tunnel bidirectional transmission before opening ports.
pub fn build_dns_probe_packet(src: Ipv4Addr) -> Vec<u8> {
    use rand::Rng;

    let dns = probe_dns_query();
    let udp_len = 8 + dns.len();
    let total_len = 20 + udp_len;

    let mut pkt = Vec::with_capacity(total_len);

    // IPv4 Header
    pkt.push(0x45); // Version 4, IHL 5
    pkt.push(0x00); // DSCP/ECN
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    let id: u16 = rand::random();
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // Flags + Frag Offset
    pkt.push(64); // TTL
    pkt.push(17); // UDP
    pkt.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&Ipv4Addr::new(8, 8, 8, 8).octets());
    let csum = ipv4_header_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());

    // UDP Header
    let sport: u16 = rand::thread_rng().gen_range(20000..60000);
    pkt.extend_from_slice(&sport.to_be_bytes());
    pkt.extend_from_slice(&53u16.to_be_bytes());
    pkt.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // Checksum optional for IPv4 UDP

    pkt.extend_from_slice(&dns);
    pkt
}

fn probe_dns_query() -> Vec<u8> {
    let id: u16 = rand::random();
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // Standard query with recursion desired
    q.extend_from_slice(&[0x00, 0x01]); // 1 question
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // 0 answers, authorities, additional
    for label in ["cloudflare", "com"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0x00); // Root label
    q.extend_from_slice(&[0x00, 0x01]); // Type A
    q.extend_from_slice(&[0x00, 0x01]); // Class IN
    q
}

fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ip_packet() -> Vec<u8> {
        let mut pkt = vec![0u8; 24];
        pkt[0] = 0x45;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[192, 168, 1, 100]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        pkt
    }

    #[test]
    fn test_varint_roundtrip() {
        for val in [0u64, 42, 63, 64, 16383, 16384, 1073741823, 1073741824, u32::MAX as u64] {
            let mut buf = Vec::new();
            encode_varint(val, &mut buf);
            assert_eq!(buf.len(), varint_len(val));
            let (decoded, consumed) = decode_varint(&buf).expect("decoded");
            assert_eq!(decoded, val);
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn test_h3_datagram_roundtrip() {
        let pkt = sample_ip_packet();
        let stream_id = 8;
        let encoded = encode_ip_datagram(stream_id, &pkt);
        let decoded = decode_ip_datagram(&encoded, stream_id)
            .expect("ok")
            .expect("payload");
        assert_eq!(decoded, pkt);

        // Mismatched stream ID should return None
        let mismatch = decode_ip_datagram(&encoded, 12).expect("ok");
        assert_eq!(mismatch, None);
    }

    #[test]
    fn test_capsule_parser_streaming() {
        let mut parser = CapsuleParser::new();
        let pkt = sample_ip_packet();
        let capsule_bytes = encode_datagram_capsule(&pkt);

        // Push partial bytes
        parser.push(&capsule_bytes[..5]);
        assert_eq!(parser.next().unwrap(), None);

        // Push remainder
        parser.push(&capsule_bytes[5..]);
        let parsed = parser.next().unwrap().expect("capsule parsed");
        match parsed {
            Capsule::Datagram(payload) => assert_eq!(payload, pkt),
            other => panic!("unexpected capsule: {:?}", other),
        }
        assert_eq!(parser.next().unwrap(), None);
    }

    #[test]
    fn test_dns_probe_packet_validity() {
        let probe = build_dns_probe_packet(Ipv4Addr::new(10, 0, 0, 2));
        assert!(looks_like_ip_packet(&probe));
        assert!(probe.len() > 28);
        assert_eq!(probe[9], 17); // UDP
    }
}
