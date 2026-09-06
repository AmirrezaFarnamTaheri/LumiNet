//! SNI strategy taxonomy ;
//! taxonomy preserved as DATA, implementation original).
//!
//! The ladder encodes which browser/client TLS fingerprints a spoofing SNI
//! impersonates, newest first. Censors whitelist specific handshake shapes, so
//! choosing an SNI alias from this table selects a fingerprint family.

/// Ordered strategy ladder: newest / most-permissive first.
pub const STRATEGY_LADDER: &[&str] = &[
    "SNI-OBFUSCATION",
    "SNI-REALITY",
    "SNI-REALITY-CHROME-149",
    "SNI-REALITY-CHROME-148",
    "SNI-REALITY-CHROME-147",
    "SNI-REALITY-CHROME-146",
    "SNI-REALITY-CHROME-145",
    "SNI-REALITY-FIREFOX-151",
    "SNI-REALITY-FIREFOX-150",
    "SNI-REALITY-FIREFOX-149",
    "SNI-REALITY-YANDEX-26.4",
    "SNI-REALITY-YANDEX-26.3",
];

/// Returns true when `name` is a recognised strategy identifier.
pub fn is_known_strategy(name: &str) -> bool {
    STRATEGY_LADDER.iter().any(|s| s.eq_ignore_ascii_case(name))
}

/// Returns the ladder position (0 = newest) or None when unknown.
pub fn strategy_rank(name: &str) -> Option<usize> {
    STRATEGY_LADDER
        .iter()
        .position(|s| s.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_ladder_entries() {
        assert!(is_known_strategy("sni-reality-chrome-148"));
        assert!(is_known_strategy("SNI-OBFUSCATION"));
        assert!(!is_known_strategy("sni-reality-chrome-999"));
    }

    #[test]
    fn ranks_newest_first() {
        assert!(strategy_rank("SNI-REALITY-CHROME-149").unwrap() < strategy_rank("SNI-REALITY-CHROME-145").unwrap());
        assert!(strategy_rank("nope").is_none());
    }
}
