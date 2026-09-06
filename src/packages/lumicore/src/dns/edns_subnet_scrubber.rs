//! EDNS Client Subnet (ECS, RFC 7871) Scrubber and DNS Cache Guard
//!
//! Inspects DNS wire-format packets, sanitizes or strips client subnet options
//! from the OPT pseudo-RR (Type 41), and recalculates ARCOUNT and payload lengths.

use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum EdnsScrubError {
    PacketTooShort,
    InvalidHeader,
    MalformedOptRecord,
}

impl fmt::Display for EdnsScrubError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketTooShort => write!(f, "DNS packet too short"),
            Self::InvalidHeader => write!(f, "Invalid DNS header"),
            Self::MalformedOptRecord => write!(f, "Malformed OPT pseudo-RR"),
        }
    }
}

impl std::error::Error for EdnsScrubError {}

#[derive(Debug, Clone, Default)]
pub struct EdnsSubnetScrubber {
    pub mask_ipv4_bits: u8,
    pub mask_ipv6_bits: u8,
    pub strip_completely: bool,
}

impl EdnsSubnetScrubber {
    pub fn new(mask_ipv4_bits: u8, mask_ipv6_bits: u8, strip_completely: bool) -> Self {
        Self {
            mask_ipv4_bits: mask_ipv4_bits.min(32),
            mask_ipv6_bits: mask_ipv6_bits.min(128),
            strip_completely,
        }
    }

    /// Masks the trailing privacy bits of an IPv4 string (e.g. "192.168.1.50" with /24 -> "192.168.1.0")
    pub fn mask_ipv4(ip: &str, mask_bits: u8) -> String {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() != 4 {
            return ip.to_string();
        }
        let mut octets = [0u8; 4];
        for (i, p) in parts.iter().enumerate() {
            if let Ok(val) = p.parse::<u8>() {
                octets[i] = val;
            } else {
                return ip.to_string();
            }
        }
        let raw = u32::from_be_bytes(octets);
        let mask = if mask_bits == 0 {
            0
        } else if mask_bits >= 32 {
            0xFFFF_FFFF
        } else {
            !((1u32 << (32 - mask_bits)) - 1)
        };
        let masked = raw & mask;
        let b = masked.to_be_bytes();
        format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
    }

    /// Scrubs ECS option (Option Code 8) from a DNS wire packet.
    /// If strip_completely is true, strips the OPT record completely and updates ARCOUNT.
    pub fn scrub_packet(&self, packet: &[u8]) -> Result<Vec<u8>, EdnsScrubError> {
        if packet.len() < 12 {
            return Err(EdnsScrubError::PacketTooShort);
        }

        let mut output = packet.to_vec();
        let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
        let ancount = u16::from_be_bytes([packet[6], packet[7]]);
        let nscount = u16::from_be_bytes([packet[8], packet[9]]);
        let arcount = u16::from_be_bytes([packet[10], packet[11]]);

        if arcount == 0 {
            return Ok(output);
        }

        // Skip header
        let mut offset = 12;

        // Skip Question Section
        for _ in 0..qdcount {
            offset = Self::skip_name(packet, offset)?;
            if offset + 4 > packet.len() {
                return Err(EdnsScrubError::PacketTooShort);
            }
            offset += 4; // QTYPE + QCLASS
        }

        // Skip Answer & Authority sections
        for _ in 0..(ancount + nscount) {
            offset = Self::skip_rr(packet, offset)?;
        }

        // Now at Additional Section. Check for OPT RR (Root domain 0x00, TYPE=41)
        let mut new_additional = Vec::new();
        let mut new_arcount = 0u16;

        for _ in 0..arcount {
            if offset >= packet.len() {
                break;
            }
            let rr_start = offset;
            let name_end = Self::skip_name(packet, offset)?;
            if name_end + 10 > packet.len() {
                return Err(EdnsScrubError::MalformedOptRecord);
            }

            let rtype = u16::from_be_bytes([packet[name_end], packet[name_end + 1]]);
            let rdlength = u16::from_be_bytes([packet[name_end + 8], packet[name_end + 9]]) as usize;
            let rdata_start = name_end + 10;
            let rdata_end = rdata_start + rdlength;

            if rdata_end > packet.len() {
                return Err(EdnsScrubError::MalformedOptRecord);
            }

            if rtype == 41 { // OPT RR
                if !self.strip_completely {
                    // Scrub ECS option 8 inside RDATA
                    let mut cleaned_rdata = Vec::new();
                    let mut r_off = rdata_start;
                    while r_off + 4 <= rdata_end {
                        let opt_code = u16::from_be_bytes([packet[r_off], packet[r_off + 1]]);
                        let opt_len = u16::from_be_bytes([packet[r_off + 2], packet[r_off + 3]]) as usize;
                        let opt_data_end = r_off + 4 + opt_len;
                        if opt_data_end > rdata_end {
                            break;
                        }
                        if opt_code != 8 { // Keep everything except ECS
                            cleaned_rdata.extend_from_slice(&packet[r_off..opt_data_end]);
                        }
                        r_off = opt_data_end;
                    }

                    // Rebuild OPT record
                    new_additional.extend_from_slice(&packet[rr_start..rdata_start - 2]);
                    new_additional.extend_from_slice(&(cleaned_rdata.len() as u16).to_be_bytes());
                    new_additional.extend_from_slice(&cleaned_rdata);
                    new_arcount += 1;
                }
            } else {
                // Non-OPT RR: preserve as-is
                new_additional.extend_from_slice(&packet[rr_start..rdata_end]);
                new_arcount += 1;
            }
            offset = rdata_end;
        }

        // Reassemble packet with new ARCOUNT
        output.truncate(12);
        output[10..12].copy_from_slice(&new_arcount.to_be_bytes());
        // Append through to start of additional section
        let header_and_body_len = packet.len() - (packet.len() - offset) - (packet.len() - offset);
        let mut reconstructed = packet[..12].to_vec();
        reconstructed[10..12].copy_from_slice(&new_arcount.to_be_bytes());
        
        // Append question + answers + authorities
        let initial_records_end = Self::find_additional_offset(packet, qdcount, ancount, nscount)?;
        reconstructed.extend_from_slice(&packet[12..initial_records_end]);
        reconstructed.extend_from_slice(&new_additional);

        Ok(reconstructed)
    }

    fn find_additional_offset(packet: &[u8], qd: u16, an: u16, ns: u16) -> Result<usize, EdnsScrubError> {
        let mut offset = 12;
        for _ in 0..qd {
            offset = Self::skip_name(packet, offset)?;
            offset += 4;
        }
        for _ in 0..(an + ns) {
            offset = Self::skip_rr(packet, offset)?;
        }
        Ok(offset)
    }

    fn skip_name(packet: &[u8], mut offset: usize) -> Result<usize, EdnsScrubError> {
        while offset < packet.len() {
            let len = packet[offset];
            if len == 0 {
                return Ok(offset + 1);
            }
            if (len & 0xC0) == 0xC0 {
                // Pointer
                return Ok(offset + 2);
            }
            offset += (len as usize) + 1;
        }
        Err(EdnsScrubError::PacketTooShort)
    }

    fn skip_rr(packet: &[u8], offset: usize) -> Result<usize, EdnsScrubError> {
        let name_end = Self::skip_name(packet, offset)?;
        if name_end + 10 > packet.len() {
            return Err(EdnsScrubError::PacketTooShort);
        }
        let rdlen = u16::from_be_bytes([packet[name_end + 8], packet[name_end + 9]]) as usize;
        let end = name_end + 10 + rdlen;
        if end > packet.len() {
            return Err(EdnsScrubError::PacketTooShort);
        }
        Ok(end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_ipv4() {
        assert_eq!(EdnsSubnetScrubber::mask_ipv4("192.168.1.50", 24), "192.168.1.0");
        assert_eq!(EdnsSubnetScrubber::mask_ipv4("10.20.30.40", 16), "10.20.0.0");
        assert_eq!(EdnsSubnetScrubber::mask_ipv4("1.2.3.4", 32), "1.2.3.4");
    }

    #[test]
    fn test_scrub_packet_no_opt() {
        let scrubber = EdnsSubnetScrubber::new(24, 56, false);
        let mut pkt = vec![0u8; 12];
        pkt[0] = 0x12; pkt[1] = 0x34; // ID
        let res = scrubber.scrub_packet(&pkt).unwrap();
        assert_eq!(res.len(), 12);
        assert_eq!(res[0], 0x12);
    }
}
