
use rand::Rng;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct PrefixRange {
    pub net: u32,
    pub mask: u32,
}

impl PrefixRange {
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.is_empty() {
            return None;
        }
        let ip = Ipv4Addr::from_str(parts[0]).ok()?;
        let prefix_len = if parts.len() > 1 {
            parts[1].parse::<u32>().ok()?
        } else {
            32
        };
        if prefix_len > 32 {
            return None;
        }
        let mask = if prefix_len == 0 {
            0
        } else {
            u32::MAX.checked_shl(32 - prefix_len).unwrap_or(0)
        };
        let net_ip = u32::from(ip) & mask;
        Some(PrefixRange { net: net_ip, mask })
    }

    pub fn randomize(&self, rand_val: u32) -> u32 {
        let host_bits = rand_val & !self.mask;
        self.net | host_bits
    }
}

#[derive(Clone, Debug)]
pub struct PortRange {
    pub min: u16,
    pub max: u16,
}

impl PortRange {
    pub fn randomize(&self, rand_val: u32) -> u16 {
        if self.min >= self.max {
            return self.min;
        }
        let range = (self.max - self.min + 1) as u32;
        self.min + (rand_val % range) as u16
    }
}

pub struct ClientIPObfuscator {
    pub active: bool,
    pub src_pfx: Option<PrefixRange>,
    pub dst_pfx: Option<PrefixRange>,
    pub sport: Option<PortRange>,
    pub dport: Option<PortRange>,
}

impl Default for ClientIPObfuscator {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientIPObfuscator {
    pub fn new() -> Self {
        ClientIPObfuscator {
            active: false,
            src_pfx: None,
            dst_pfx: None,
            sport: None,
            dport: None,
        }
    }

    pub fn configure(
        &mut self,
        src_cidr: Option<&str>,
        dst_cidr: Option<&str>,
        sport_range: Option<(u16, u16)>,
        dport_range: Option<(u16, u16)>,
    ) {
        self.active = true;
        self.src_pfx = src_cidr.and_then(PrefixRange::parse);
        self.dst_pfx = dst_cidr.and_then(PrefixRange::parse);
        self.sport = sport_range.map(|(min, max)| PortRange { min, max });
        self.dport = dport_range.map(|(min, max)| PortRange { min, max });
    }

    /// Statelessly mangles raw packet IP headers and TCP/UDP ports,
    /// recalculating IPv4 and TCP checksums in place.
    pub fn mangle_packet(&self, raw: &mut [u8]) -> bool {
        if !self.active || raw.len() < 20 {
            return false;
        }

        // Verify version is IPv4 (0x45 or similar where version is top 4 bits)
        let version = raw[0] >> 4;
        if version != 4 {
            return false;
        }

        let ip_hdr_len = ((raw[0] & 0x0F) * 4) as usize;
        if raw.len() < ip_hdr_len {
            return false;
        }

        let proto = raw[9];
        let mut changed = false;

        let mut rng = rand::thread_rng();

        // 1. Mangle Source IP
        if let Some(ref pfx) = self.src_pfx {
            let old_ip = u32::from_be_bytes([raw[12], raw[13], raw[14], raw[15]]);
            if (old_ip & pfx.mask) == pfx.net {
                let rand_val = rng.gen::<u32>();
                let new_ip = pfx.randomize(rand_val);
                raw[12..16].copy_from_slice(&new_ip.to_be_bytes());
                changed = true;
            }
        }

        // 2. Mangle Destination IP
        if let Some(ref pfx) = self.dst_pfx {
            let old_ip = u32::from_be_bytes([raw[16], raw[17], raw[18], raw[19]]);
            if (old_ip & pfx.mask) == pfx.net {
                let rand_val = rng.gen::<u32>();
                let new_ip = pfx.randomize(rand_val);
                raw[16..20].copy_from_slice(&new_ip.to_be_bytes());
                changed = true;
            }
        }

        // 3. Mangle L4 Ports (TCP or UDP)
        if proto == 6 && raw.len() >= ip_hdr_len + 20 {
            // TCP
            if let Some(ref r) = self.sport {
                let rand_val = rng.gen::<u32>();
                let new_port = r.randomize(rand_val);
                raw[ip_hdr_len..ip_hdr_len + 2].copy_from_slice(&new_port.to_be_bytes());
                changed = true;
            }
            if let Some(ref r) = self.dport {
                let rand_val = rng.gen::<u32>();
                let new_port = r.randomize(rand_val);
                raw[ip_hdr_len + 2..ip_hdr_len + 4].copy_from_slice(&new_port.to_be_bytes());
                changed = true;
            }
        } else if proto == 17 && raw.len() >= ip_hdr_len + 8 {
            // UDP
            if let Some(ref r) = self.sport {
                let rand_val = rng.gen::<u32>();
                let new_port = r.randomize(rand_val);
                raw[ip_hdr_len..ip_hdr_len + 2].copy_from_slice(&new_port.to_be_bytes());
                changed = true;
            }
            if let Some(ref r) = self.dport {
                let rand_val = rng.gen::<u32>();
                let new_port = r.randomize(rand_val);
                raw[ip_hdr_len + 2..ip_hdr_len + 4].copy_from_slice(&new_port.to_be_bytes());
                changed = true;
            }
        }

        if changed {
            // Recalculate checksums using existing header helpers
            super::packet_header::compute_ip_checksum(raw);
            if proto == 6 {
                super::packet_header::compute_tcp_checksum(raw);
            }
        }

        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_range() {
        let pfx = PrefixRange::parse("10.0.0.0/24").unwrap();
        assert_eq!(pfx.net, 0x0A000000);
        assert_eq!(pfx.mask, 0xFFFFFF00);

        let rand_ip = pfx.randomize(123);
        assert_eq!(rand_ip, 0x0A000000 | 123);
    }

    #[test]
    fn test_port_range() {
        let pr = PortRange {
            min: 1000,
            max: 2000,
        };
        let rand_port = pr.randomize(12345);
        assert!((1000..=2000).contains(&rand_port));
    }

    #[test]
    fn test_mangle_packet() {
        // Construct dummy IPv4 TCP packet
        let mut raw = vec![0u8; 40];
        // IPv4 Header with len=20
        raw[0] = 0x45;
        raw[9] = 6; // TCP
                    // Src IP: 10.0.0.50
        raw[12..16].copy_from_slice(&[10, 0, 0, 50]);
        // Dst IP: 192.168.1.100
        raw[16..20].copy_from_slice(&[192, 168, 1, 100]);

        // TCP Header (ip_hdr_len=20)
        // Src Port: 5000
        raw[20..22].copy_from_slice(&5000u16.to_be_bytes());
        // Dst Port: 80
        raw[22..24].copy_from_slice(&80u16.to_be_bytes());

        let mut obfs = ClientIPObfuscator::new();
        obfs.configure(Some("10.0.0.0/24"), None, Some((10000, 11000)), None);

        let res = obfs.mangle_packet(&mut raw);
        assert!(res);

        // Verify Src IP changed but is still in 10.0.0.0/24
        assert_eq!(raw[12], 10);
        assert_eq!(raw[13], 0);
        assert_eq!(raw[14], 0);
        assert!(raw[15] != 50); // should be randomized

        // Verify Src Port changed and is in range
        let new_sport = u16::from_be_bytes([raw[20], raw[21]]);
        assert!((10000..=11000).contains(&new_sport));
    }
}
