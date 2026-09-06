//! # Enhanced GeoIP CIDR Database Lookup
//!
//! Provides fast longest-prefix-match IP to ISO country code mapping and
//! private/bogon range classification.

#[derive(Debug, Clone)]
pub struct GeoCidrEntry {
    pub net_addr: u32,
    pub mask: u32,
    pub country_code: String,
}

pub struct EnhancedGeoIpLookup {
    entries: Vec<GeoCidrEntry>,
}

impl EnhancedGeoIpLookup {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    pub fn add_cidr(&mut self, octets: [u8; 4], mask_bits: u8, country_code: &str) {
        let ip_u32 = u32::from_be_bytes(octets);
        let mask = if mask_bits == 0 {
            0u32
        } else {
            !0u32 << (32 - mask_bits)
        };
        self.entries.push(GeoCidrEntry {
            net_addr: ip_u32 & mask,
            mask,
            country_code: country_code.trim().to_uppercase(),
        });
    }

    pub fn lookup(&self, octets: [u8; 4]) -> Option<&str> {
        let ip_u32 = u32::from_be_bytes(octets);
        let mut best_match: Option<(&str, u32)> = None;

        for entry in &self.entries {
            if (ip_u32 & entry.mask) == entry.net_addr {
                match best_match {
                    Some((_, best_mask)) => {
                        if entry.mask > best_mask {
                            best_match = Some((&entry.country_code, entry.mask));
                        }
                    }
                    None => {
                        best_match = Some((&entry.country_code, entry.mask));
                    }
                }
            }
        }

        best_match.map(|(cc, _)| cc)
    }

    pub fn is_private(octets: [u8; 4]) -> bool {
        match octets[0] {
            10 => true,
            127 => true,
            172 => (16..=31).contains(&octets[1]),
            192 => octets[1] == 168,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enhanced_geoip_lookup() {
        let mut geo = EnhancedGeoIpLookup::new();
        geo.add_cidr([1, 0, 1, 0], 24, "CN");
        geo.add_cidr([8, 8, 8, 0], 24, "US");
        geo.add_cidr([8, 8, 0, 0], 16, "US-BROAD");

        assert_eq!(geo.lookup([1, 0, 1, 55]), Some("CN"));
        // Longest prefix match: /24 should beat /16
        assert_eq!(geo.lookup([8, 8, 8, 8]), Some("US"));
        assert_eq!(geo.lookup([8, 8, 10, 1]), Some("US-BROAD"));
        assert_eq!(geo.lookup([9, 9, 9, 9]), None);

        assert!(EnhancedGeoIpLookup::is_private([192, 168, 1, 1]));
        assert!(EnhancedGeoIpLookup::is_private([10, 0, 0, 1]));
        assert!(!EnhancedGeoIpLookup::is_private([8, 8, 8, 8]));
    }
}
