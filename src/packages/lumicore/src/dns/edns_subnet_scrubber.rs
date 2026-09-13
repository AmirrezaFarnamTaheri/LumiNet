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

        let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
        let ancount = u16::from_be_bytes([packet[6], packet[7]]);
        let nscount = u16::from_be_bytes([packet[8], packet[9]]);
        let arcount = u16::from_be_bytes([packet[10], packet[11]]);

        if arcount == 0 {
            return Ok(packet.to_vec());
        }

        let mut offset = 12;

        for _ in 0..qdcount {
            offset = Self::skip_name(packet, offset)?;
            offset = offset
                .checked_add(4)
                .filter(|end| *end <= packet.len())
                .ok_or(EdnsScrubError::PacketTooShort)?;
        }

        for _ in 0..(ancount + nscount) {
            offset = Self::skip_rr(packet, offset)?;
        }

        let additional_start = offset;
        let mut new_additional = Vec::new();
        let mut new_arcount = 0u16;

        for _ in 0..arcount {
            if offset >= packet.len() {
                return Err(EdnsScrubError::MalformedOptRecord);
            }

            let rr_start = offset;
            let name_end = Self::skip_name(packet, offset)?;
            let fixed_end = name_end
                .checked_add(10)
                .filter(|end| *end <= packet.len())
                .ok_or(EdnsScrubError::MalformedOptRecord)?;

            let rtype = u16::from_be_bytes([packet[name_end], packet[name_end + 1]]);
            let rdlength = u16::from_be_bytes([packet[name_end + 8], packet[name_end + 9]]) as usize;
            let rdata_start = fixed_end;
            let rdata_end = rdata_start
                .checked_add(rdlength)
                .filter(|end| *end <= packet.len())
                .ok_or(EdnsScrubError::MalformedOptRecord)?;

            if rtype == 41 {
                if !self.strip_completely {
                    let mut cleaned_rdata = Vec::new();
                    let mut r_off = rdata_start;
                    while r_off < rdata_end {
                        let option_header_end = r_off
                            .checked_add(4)
                            .filter(|end| *end <= rdata_end)
                            .ok_or(EdnsScrubError::MalformedOptRecord)?;
                        let opt_code = u16::from_be_bytes([packet[r_off], packet[r_off + 1]]);
                        let opt_len =
                            u16::from_be_bytes([packet[r_off + 2], packet[r_off + 3]]) as usize;
                        let opt_data_end = option_header_end
                            .checked_add(opt_len)
                            .filter(|end| *end <= rdata_end)
                            .ok_or(EdnsScrubError::MalformedOptRecord)?;

                        if opt_code != 8 {
                            cleaned_rdata.extend_from_slice(&packet[r_off..opt_data_end]);
                        }
                        r_off = opt_data_end;
                    }

                    let cleaned_len = u16::try_from(cleaned_rdata.len())
                        .map_err(|_| EdnsScrubError::MalformedOptRecord)?;
                    new_additional.extend_from_slice(&packet[rr_start..rdata_start - 2]);
                    new_additional.extend_from_slice(&cleaned_len.to_be_bytes());
                    new_additional.extend_from_slice(&cleaned_rdata);
                    new_arcount += 1;
                }
            } else {
                new_additional.extend_from_slice(&packet[rr_start..rdata_end]);
                new_arcount += 1;
            }
            offset = rdata_end;
        }

        let mut reconstructed = packet[..additional_start].to_vec();
        reconstructed[10..12].copy_from_slice(&new_arcount.to_be_bytes());
        reconstructed.extend_from_slice(&new_additional);
        Ok(reconstructed)
    }

    fn skip_name(packet: &[u8], mut offset: usize) -> Result<usize, EdnsScrubError> {
        while offset < packet.len() {
            let len = packet[offset];
            if len == 0 {
                return Ok(offset + 1);
            }
            if (len & 0xC0) == 0xC0 {
                return offset
                    .checked_add(2)
                    .filter(|end| *end <= packet.len())
                    .ok_or(EdnsScrubError::PacketTooShort);
            }
            if (len & 0xC0) != 0 {
                return Err(EdnsScrubError::InvalidHeader);
            }
            offset = offset
                .checked_add((len as usize) + 1)
                .filter(|next| *next <= packet.len())
                .ok_or(EdnsScrubError::PacketTooShort)?;
        }
        Err(EdnsScrubError::PacketTooShort)
    }

    fn skip_rr(packet: &[u8], offset: usize) -> Result<usize, EdnsScrubError> {
        let name_end = Self::skip_name(packet, offset)?;
        let fixed_end = name_end
            .checked_add(10)
            .filter(|end| *end <= packet.len())
            .ok_or(EdnsScrubError::PacketTooShort)?;
        let rdlen = u16::from_be_bytes([packet[name_end + 8], packet[name_end + 9]]) as usize;
        fixed_end
            .checked_add(rdlen)
            .filter(|end| *end <= packet.len())
            .ok_or(EdnsScrubError::PacketTooShort)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opt_packet(rdata: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 12];
        packet[10..12].copy_from_slice(&1u16.to_be_bytes());
        packet.push(0); // root owner name
        packet.extend_from_slice(&41u16.to_be_bytes());
        packet.extend_from_slice(&1232u16.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(rdata);
        packet
    }

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
        pkt[0] = 0x12;
        pkt[1] = 0x34;
        let res = scrubber.scrub_packet(&pkt).unwrap();
        assert_eq!(res.len(), 12);
        assert_eq!(res[0], 0x12);
    }

    #[test]
    fn test_scrub_packet_removes_ecs_but_preserves_other_options() {
        let scrubber = EdnsSubnetScrubber::new(24, 56, false);
        let rdata = [
            0, 8, 0, 4, 0, 1, 24, 0, // ECS
            0, 12, 0, 2, 0xaa, 0xbb, // padding/other option
        ];
        let result = scrubber.scrub_packet(&opt_packet(&rdata)).unwrap();

        assert_eq!(u16::from_be_bytes([result[10], result[11]]), 1);
        assert_eq!(u16::from_be_bytes([result[21], result[22]]), 6);
        assert_eq!(&result[23..], &[0, 12, 0, 2, 0xaa, 0xbb]);
    }

    #[test]
    fn test_scrub_packet_rejects_truncated_option_header() {
        let scrubber = EdnsSubnetScrubber::new(24, 56, false);
        let err = scrubber.scrub_packet(&opt_packet(&[0, 8, 0])).unwrap_err();
        assert_eq!(err, EdnsScrubError::MalformedOptRecord);
    }

    #[test]
    fn test_scrub_packet_rejects_truncated_option_payload() {
        let scrubber = EdnsSubnetScrubber::new(24, 56, false);
        let err = scrubber
            .scrub_packet(&opt_packet(&[0, 8, 0, 4, 0, 1]))
            .unwrap_err();
        assert_eq!(err, EdnsScrubError::MalformedOptRecord);
    }

    #[test]
    fn test_strip_opt_updates_arcount() {
        let scrubber = EdnsSubnetScrubber::new(24, 56, true);
        let result = scrubber.scrub_packet(&opt_packet(&[0, 8, 0, 0])).unwrap();
        assert_eq!(u16::from_be_bytes([result[10], result[11]]), 0);
        assert_eq!(result.len(), 12);
    }
}
