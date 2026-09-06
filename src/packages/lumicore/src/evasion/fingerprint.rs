//! # Browser Fingerprint
//!
//! Unified browser TLS fingerprint enum consolidating all variants.
//! Merges: tls_evasion::BrowserFingerprint (7 variants) + sni_spoof::TlsFingerprint (19 variants).
//!
//! The 19-variant version provides version-specific fingerprints for precise mimicry.
//! The 7-variant version provides browser-level shortcuts that auto-select the latest.

/// Browser fingerprint for TLS ClientHello mimicry.
/// 19 version-specific variants + 7 browser-level auto-aliases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BrowserFingerprint {
    // Chrome versions
    Chrome58,
    Chrome62,
    Chrome70,
    Chrome72,
    Chrome83,
    Chrome87,
    Chrome96,
    Chrome100,
    Chrome102,
    Chrome106Shuffle,
    Chrome112PskShuf,
    Chrome114PaddingPskShuf,
    Chrome115Pq,
    Chrome115PqPsk,
    Chrome120,
    Chrome120Pq,
    Chrome131,
    Chrome133,
    // Firefox versions
    Firefox55,
    Firefox56,
    Firefox63,
    Firefox65,
    Firefox99,
    Firefox102,
    Firefox105,
    Firefox120,
    // Safari versions
    Safari16,
    // iOS versions
    IOS11_1,
    IOS12_1,
    IOS13,
    IOS14,
    // Edge versions
    Edge85,
    Edge106,
    // Android
    Android11OkHttp,
    // QQ
    QQ11_1,
    // 360
    Browser360_7_5,
    Browser360_11_0,
    // Special
    Golang,
    Random,
    RandomizedALPN,
    RandomizedNoALPN,
    // Auto aliases (select latest version)
    Chrome,
    Firefox,
    Safari,
    Edge,
    IOS,
    QQ,
    Browser360,
}

impl BrowserFingerprint {
    /// Returns the fingerprint name string.
    pub fn as_str(&self) -> &'static str {
        match self {
            // Chrome
            Self::Chrome58 => "chrome58",
            Self::Chrome62 => "chrome62",
            Self::Chrome70 => "chrome70",
            Self::Chrome72 => "chrome72",
            Self::Chrome83 => "chrome83",
            Self::Chrome87 => "chrome87",
            Self::Chrome96 => "chrome96",
            Self::Chrome100 => "chrome100",
            Self::Chrome102 => "chrome102",
            Self::Chrome106Shuffle => "chrome106_shuffle",
            Self::Chrome112PskShuf => "chrome112_psk_shuf",
            Self::Chrome114PaddingPskShuf => "chrome114_padding_psk_shuf",
            Self::Chrome115Pq => "chrome115_pq",
            Self::Chrome115PqPsk => "chrome115_pq_psk",
            Self::Chrome120 => "chrome120",
            Self::Chrome120Pq => "chrome120_pq",
            Self::Chrome131 => "chrome131",
            Self::Chrome133 => "chrome133",
            // Firefox
            Self::Firefox55 => "firefox55",
            Self::Firefox56 => "firefox56",
            Self::Firefox63 => "firefox63",
            Self::Firefox65 => "firefox65",
            Self::Firefox99 => "firefox99",
            Self::Firefox102 => "firefox102",
            Self::Firefox105 => "firefox105",
            Self::Firefox120 => "firefox120",
            // Safari
            Self::Safari16 => "safari16",
            // iOS
            Self::IOS11_1 => "ios11_1",
            Self::IOS12_1 => "ios12_1",
            Self::IOS13 => "ios13",
            Self::IOS14 => "ios14",
            // Edge
            Self::Edge85 => "edge85",
            Self::Edge106 => "edge106",
            // Android
            Self::Android11OkHttp => "android11_okhttp",
            // QQ
            Self::QQ11_1 => "qq11_1",
            // 360
            Self::Browser360_7_5 => "360_7_5",
            Self::Browser360_11_0 => "360_11_0",
            // Special
            Self::Golang => "golang",
            Self::Random => "random",
            Self::RandomizedALPN => "randomizedalpn",
            Self::RandomizedNoALPN => "randomizednoalpn",
            // Auto aliases
            Self::Chrome => "chrome",
            Self::Firefox => "firefox",
            Self::Safari => "safari",
            Self::Edge => "edge",
            Self::IOS => "ios",
            Self::QQ => "qq",
            Self::Browser360 => "360browser",
        }
    }

    /// Parses a fingerprint name string into a BrowserFingerprint.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.to_lowercase();
        match s.as_str() {
            "chrome" => Some(Self::Chrome),
            "firefox" => Some(Self::Firefox),
            "safari" => Some(Self::Safari),
            "edge" => Some(Self::Edge),
            "ios" => Some(Self::IOS),
            "qq" => Some(Self::QQ),
            "360browser" | "360" => Some(Self::Browser360),
            "random" => Some(Self::Random),
            "golang" => Some(Self::Golang),
            _ => {
                // Try exact match
                for fp in Self::all_variants() {
                    if fp.as_str() == s {
                        return Some(fp);
                    }
                }
                None
            }
        }
    }

    /// Returns all version-specific variants (excludes auto aliases).
    pub fn all_variants() -> Vec<Self> {
        vec![
            Self::Chrome58,
            Self::Chrome62,
            Self::Chrome70,
            Self::Chrome72,
            Self::Chrome83,
            Self::Chrome87,
            Self::Chrome96,
            Self::Chrome100,
            Self::Chrome102,
            Self::Chrome106Shuffle,
            Self::Chrome112PskShuf,
            Self::Chrome114PaddingPskShuf,
            Self::Chrome115Pq,
            Self::Chrome115PqPsk,
            Self::Chrome120,
            Self::Chrome120Pq,
            Self::Chrome131,
            Self::Chrome133,
            Self::Firefox55,
            Self::Firefox56,
            Self::Firefox63,
            Self::Firefox65,
            Self::Firefox99,
            Self::Firefox102,
            Self::Firefox105,
            Self::Firefox120,
            Self::Safari16,
            Self::IOS11_1,
            Self::IOS12_1,
            Self::IOS13,
            Self::IOS14,
            Self::Edge85,
            Self::Edge106,
            Self::Android11OkHttp,
            Self::QQ11_1,
            Self::Browser360_7_5,
            Self::Browser360_11_0,
            Self::Golang,
            Self::Random,
            Self::RandomizedALPN,
            Self::RandomizedNoALPN,
        ]
    }

    /// Returns the latest version for a browser family.
    pub fn latest_for_browser(browser: &str) -> Self {
        match browser.to_lowercase().as_str() {
            "chrome" => Self::Chrome133,
            "firefox" => Self::Firefox120,
            "safari" => Self::Safari16,
            "edge" => Self::Edge106,
            "ios" => Self::IOS14,
            "qq" => Self::QQ11_1,
            "360" => Self::Browser360_11_0,
            _ => Self::Random,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_variants() {
        let variants = BrowserFingerprint::all_variants();
        assert!(variants.len() >= 40);
    }

    #[test]
    fn test_from_str() {
        assert_eq!(
            BrowserFingerprint::parse("chrome"),
            Some(BrowserFingerprint::Chrome)
        );
        assert_eq!(
            BrowserFingerprint::parse("firefox"),
            Some(BrowserFingerprint::Firefox)
        );
        assert_eq!(
            BrowserFingerprint::parse("Chrome120"),
            Some(BrowserFingerprint::Chrome120)
        );
        assert_eq!(BrowserFingerprint::parse("unknown"), None);
    }

    #[test]
    fn test_as_str() {
        assert_eq!(BrowserFingerprint::Chrome120.as_str(), "chrome120");
        assert_eq!(BrowserFingerprint::Firefox120.as_str(), "firefox120");
    }

    #[test]
    fn test_latest_for_browser() {
        assert_eq!(
            BrowserFingerprint::latest_for_browser("chrome"),
            BrowserFingerprint::Chrome133
        );
        assert_eq!(
            BrowserFingerprint::latest_for_browser("firefox"),
            BrowserFingerprint::Firefox120
        );
    }

    #[test]
    fn test_roundtrip() {
        for fp in BrowserFingerprint::all_variants() {
            let name = fp.as_str();
            let parsed = BrowserFingerprint::parse(name);
            assert_eq!(parsed, Some(fp), "Failed roundtrip for {}", name);
        }
    }
}
