//! # Government IP Blocklist
//!
//! Curated list of IP subnets belonging to government agencies and state-controlled
//! entities. Used for traffic classification, routing decisions, and security filtering.
//!
//! Data organized by category for efficient lookup and filtering.

use crate::routing::IpRoutingTrie;
use std::net::IpAddr;
use std::sync::OnceLock;

/// Category of government entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GovCategory {
    /// Federal agencies (FSB, FSO, MVD, etc.)
    FederalAgency,
    /// Law enforcement (investigative committee, prosecutors)
    LawEnforcement,
    /// Regional government (dumas, regional offices)
    RegionalGovernment,
    /// Emergency services (MChS)
    EmergencyServices,
    /// Regulatory bodies (Rospotrebnadzor, Rospatent)
    Regulatory,
    /// State media (VGTRK, ORT, NTV)
    StateMedia,
    /// State-adjacent entities (Rosatom, Goznak)
    StateAdjacent,
    /// Copyright enforcement
    CopyrightEnforcement,
}

/// A government IP range entry with metadata.
#[derive(Debug, Clone)]
pub struct GovIpEntry {
    pub cidr: &'static str,
    pub name_en: &'static str,
    pub name_ru: &'static str,
    pub category: GovCategory,
    pub asn: Option<&'static str>,
}

/// Static government IP blocklist data.
/// Format: (CIDR, English name, Russian name, Category, ASN)
pub static GOV_BLOCKLIST: &[GovIpEntry] = &[
    // Federal Agencies
    GovIpEntry {
        cidr: "193.232.128.0/18",
        name_en: "Roskomnadzor",
        name_ru: "Роскомнадзор",
        category: GovCategory::FederalAgency,
        asn: Some("AS12389"),
    },
    GovIpEntry {
        cidr: "194.85.30.0/23",
        name_en: "FSB",
        name_ru: "ФСБ",
        category: GovCategory::FederalAgency,
        asn: Some("AS57487"),
    },
    GovIpEntry {
        cidr: "84.237.52.0/22",
        name_en: "FSO",
        name_ru: "ФСО",
        category: GovCategory::FederalAgency,
        asn: Some("AS57487"),
    },
    GovIpEntry {
        cidr: "195.208.128.0/18",
        name_en: "MVD",
        name_ru: "МВД",
        category: GovCategory::FederalAgency,
        asn: Some("AS48133"),
    },
    GovIpEntry {
        cidr: "213.24.76.0/22",
        name_en: "FNS (Tax)",
        name_ru: "ФНС",
        category: GovCategory::FederalAgency,
        asn: Some("AS47238"),
    },
    GovIpEntry {
        cidr: "194.190.16.0/20",
        name_en: "MinJust",
        name_ru: "Минюст",
        category: GovCategory::FederalAgency,
        asn: Some("AS47238"),
    },
    GovIpEntry {
        cidr: "82.179.160.0/19",
        name_en: "MID (Foreign Affairs)",
        name_ru: "МИД",
        category: GovCategory::FederalAgency,
        asn: Some("AS47238"),
    },
    // Law Enforcement
    GovIpEntry {
        cidr: "95.173.128.0/19",
        name_en: "Investigative Committee",
        name_ru: "Следственный комитет",
        category: GovCategory::LawEnforcement,
        asn: Some("AS47238"),
    },
    GovIpEntry {
        cidr: "194.8.240.0/22",
        name_en: "Prosecutors (Moscow)",
        name_ru: "Прокуратура (Москва)",
        category: GovCategory::LawEnforcement,
        asn: Some("AS47238"),
    },
    GovIpEntry {
        cidr: "82.151.128.0/19",
        name_en: "FSIN (Prison System)",
        name_ru: "ФСИН",
        category: GovCategory::LawEnforcement,
        asn: Some("AS47238"),
    },
    // Regional Government
    GovIpEntry {
        cidr: "212.41.0.0/18",
        name_en: "Moscow Duma",
        name_ru: "Московская дума",
        category: GovCategory::RegionalGovernment,
        asn: Some("AS47238"),
    },
    GovIpEntry {
        cidr: "195.230.128.0/17",
        name_en: "Sverdlovsk Regional Gov",
        name_ru: "Свердловская область",
        category: GovCategory::RegionalGovernment,
        asn: Some("AS47238"),
    },
    // State Media
    GovIpEntry {
        cidr: "195.16.64.0/18",
        name_en: "VGTRK",
        name_ru: "ВГТРК",
        category: GovCategory::StateMedia,
        asn: Some("AS47238"),
    },
    GovIpEntry {
        cidr: "89.208.208.0/20",
        name_en: "RIA Novosti",
        name_ru: "РИА Новости",
        category: GovCategory::StateMedia,
        asn: Some("AS47238"),
    },
    // State-Adjacent
    GovIpEntry {
        cidr: "178.176.128.0/17",
        name_en: "Rosatom",
        name_ru: "Росатом",
        category: GovCategory::StateAdjacent,
        asn: Some("AS47238"),
    },
    GovIpEntry {
        cidr: "212.75.192.0/18",
        name_en: "Goznak",
        name_ru: "Гознак",
        category: GovCategory::StateAdjacent,
        asn: Some("AS47238"),
    },
    GovIpEntry {
        cidr: "213.85.0.0/18",
        name_en: "GlavNIVTs (Presidential Admin)",
        name_ru: "ГлавНИВЦ",
        category: GovCategory::StateAdjacent,
        asn: Some("AS47238"),
    },
    // Copyright Enforcement
    GovIpEntry {
        cidr: "91.206.184.0/22",
        name_en: "fzpr.ru",
        name_ru: "fzpr.ru",
        category: GovCategory::CopyrightEnforcement,
        asn: None,
    },
    GovIpEntry {
        cidr: "185.26.112.0/22",
        name_en: "rp-union.ru",
        name_ru: "rp-union.ru",
        category: GovCategory::CopyrightEnforcement,
        asn: None,
    },
];

/// Global trie index for O(lookup) government IP classification.
static GOV_TRIE: OnceLock<IpRoutingTrie<(GovCategory, &'static str)>> = OnceLock::new();

/// Initializes the government IP trie (lazy, thread-safe).
fn get_gov_trie() -> &'static IpRoutingTrie<(GovCategory, &'static str)> {
    GOV_TRIE.get_or_init(|| {
        let mut trie = IpRoutingTrie::new();
        for entry in GOV_BLOCKLIST {
            // Parse CIDR and insert into trie
            if let Some((ip, prefix_len)) = parse_cidr_prefix(entry.cidr) {
                trie.insert(&ip, prefix_len, (entry.category, entry.name_en));
            }
        }
        trie
    })
}

/// Parses "x.x.x.x/nn" into (IpAddr, prefix_len).
fn parse_cidr_prefix(cidr: &str) -> Option<(IpAddr, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip: IpAddr = parts[0].parse().ok()?;
    let prefix: u8 = parts[1].parse().ok()?;
    Some((ip, prefix))
}

/// Checks if an IP address belongs to a known government entity.
/// Returns the category and name if found.
pub fn classify_gov_ip(ip: &IpAddr) -> Option<(GovCategory, &'static str)> {
    let trie = get_gov_trie();
    trie.longest_match(ip).copied()
}

/// Returns true if the IP belongs to a government entity.
pub fn is_government_ip(ip: &IpAddr) -> bool {
    classify_gov_ip(ip).is_some()
}

/// Returns all government IP entries for a specific category.
pub fn entries_by_category(category: GovCategory) -> Vec<&'static GovIpEntry> {
    GOV_BLOCKLIST
        .iter()
        .filter(|e| e.category == category)
        .collect()
}

/// Returns the total number of government CIDR entries.
pub fn blocklist_size() -> usize {
    GOV_BLOCKLIST.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gov_ip_detection() {
        // Roskomnadzor range
        let ip: IpAddr = "193.232.128.1".parse().unwrap();
        assert!(is_government_ip(&ip));
        let (cat, name) = classify_gov_ip(&ip).unwrap();
        assert_eq!(cat, GovCategory::FederalAgency);
        assert_eq!(name, "Roskomnadzor");
    }

    #[test]
    fn test_non_gov_ip() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!is_government_ip(&ip));
    }

    #[test]
    fn test_category_filtering() {
        let media = entries_by_category(GovCategory::StateMedia);
        assert!(!media.is_empty());
        for entry in media {
            assert_eq!(entry.category, GovCategory::StateMedia);
        }
    }

    #[test]
    fn test_blocklist_not_empty() {
        assert!(blocklist_size() > 0);
    }
}
