
use std::collections::HashSet;

/// IDNSanitizer detects IDN homograph spoofing attacks and sanitizes suspicious domains into punycode format.
pub struct IDNSanitizer {
    pub active: bool,
}

impl Default for IDNSanitizer {
    fn default() -> Self {
        Self::new()
    }
}

impl IDNSanitizer {
    pub fn new() -> Self {
        IDNSanitizer { active: true }
    }

    /// Check if a domain contains a homograph spoofing attack.
    /// Returns true if an attack is detected.
    pub fn detect_attack(&self, domain: &str) -> bool {
        if !self.active {
            return false;
        }

        let domain_lower = domain.to_lowercase();
        let parts: Vec<&str> = domain_lower.split('.').collect();
        if parts.len() < 2 {
            return false;
        }
        let tld = parts[parts.len() - 1];

        // Check each label (excluding the TLD itself)
        for label in parts.iter().take(parts.len() - 1) {
            if label.is_empty() || label.starts_with("xn--") {
                continue;
            }

            if self.has_disallowed_characters(label)
                || self.has_mixed_scripts(label)
                || self.has_mixed_digits(label)
                || self.has_dangerous_patterns(label)
                || self.has_deviation_characters(label)
                || self.has_script_confusables(label, tld)
                || self.has_script_specific_spoofs(label, tld)
            {
                return true;
            }
        }

        false
    }

    /// Sanitize a domain. If a spoofing attack is detected, suspicious labels are punycode-encoded.
    pub fn sanitize(&self, domain: &str) -> String {
        if !self.active || !self.detect_attack(domain) {
            return domain.to_string();
        }

        let mut parts = Vec::new();
        let original_parts: Vec<&str> = domain.split('.').collect();
        if original_parts.len() < 2 {
            return domain.to_string();
        }
        let tld = original_parts[original_parts.len() - 1].to_lowercase();

        for i in 0..original_parts.len() {
            let label = original_parts[i];
            if i == original_parts.len() - 1 {
                parts.push(label.to_string());
                continue;
            }

            if label.starts_with("xn--") || label.is_empty() {
                parts.push(label.to_string());
                continue;
            }

            // Check if the individual label is suspicious
            let label_lower = label.to_lowercase();
            if self.has_disallowed_characters(&label_lower)
                || self.has_mixed_scripts(&label_lower)
                || self.has_mixed_digits(&label_lower)
                || self.has_dangerous_patterns(&label_lower)
                || self.has_deviation_characters(&label_lower)
                || self.has_script_confusables(&label_lower, &tld)
                || self.has_script_specific_spoofs(&label_lower, &tld)
            {
                if let Some(encoded) = self.punycode_encode(&label_lower) {
                    parts.push(format!("xn--{}", encoded));
                } else {
                    parts.push(label.to_string());
                }
            } else {
                parts.push(label.to_string());
            }
        }

        parts.join(".")
    }

    /// Identifies if the label contains disallowed punctuation/format characters commonly used in attacks.
    fn has_disallowed_characters(&self, label: &str) -> bool {
        for c in label.chars() {
            let val = c as u32;
            match val {
                // Zero-width and whitespace characters
                0x0020
                | 0x00A0
                | 0x2000..=0x200B
                | 0x200E
                | 0x200F
                | 0x2028
                | 0x2029
                | 0x3000
                | 0xFEFF => return true,
                // Vulgar fractions
                0x00BC | 0x00BD | 0x00BE | 0x2153..=0x215F => return true,
                // Solidus overlays and fraction slashes
                0x0337 | 0x0338 | 0x2044 | 0x2215 | 0xFF0F | 0xFF61 => return true,
                // Clicks and triangular colons
                0x01C3 | 0x02D0 | 0xA789 => return true,
                _ => {}
            }
        }
        false
    }

    /// Checks if a label mixes scripts violating UTS #39 Highly Restrictive combinations.
    fn has_mixed_scripts(&self, label: &str) -> bool {
        let mut scripts = HashSet::new();
        for c in label.chars() {
            if c == '-' || c.is_ascii_digit() {
                continue;
            }
            if let Some(script) = self.get_char_script(c) {
                scripts.insert(script);
            }
        }

        if scripts.len() <= 1 {
            return false;
        }

        // Check Highly Restrictive Combinations (Japanese, Chinese, Korean + Latin subsets)
        let is_japanese = scripts
            .iter()
            .all(|&s| s == "Han" || s == "Hiragana" || s == "Katakana" || s == "Latin");
        let is_chinese = scripts
            .iter()
            .all(|&s| s == "Han" || s == "Bopomofo" || s == "Latin");
        let is_korean = scripts
            .iter()
            .all(|&s| s == "Han" || s == "Hangul" || s == "Latin");

        !(is_japanese || is_chinese || is_korean)
    }

    /// Check if digits from multiple scripts are mixed in the same label.
    fn has_mixed_digits(&self, label: &str) -> bool {
        let mut digit_scripts = HashSet::new();
        for c in label.chars() {
            let val = c as u32;
            if c.is_ascii_digit() {
                digit_scripts.insert("Latin");
            } else if (0x0660..=0x0669).contains(&val) {
                digit_scripts.insert("Arabic-Indic");
            } else if (0x06F0..=0x06F9).contains(&val) {
                digit_scripts.insert("Eastern-Arabic-Indic");
            }
        }
        digit_scripts.len() > 1
    }

    /// Check for dangerous CJK ideographs placed next to non-CJK characters.
    fn has_dangerous_patterns(&self, label: &str) -> bool {
        let chars: Vec<char> = label.chars().collect();
        for i in 0..chars.len() {
            let c = chars[i];
            if self.is_dangerous_cjk_char(c) {
                // Check left neighbor
                if i > 0 && !self.is_cjk_char(chars[i - 1]) {
                    return true;
                }
                // Check right neighbor
                if i + 1 < chars.len() && !self.is_cjk_char(chars[i + 1]) {
                    return true;
                }
            }
        }
        false
    }

    /// IDNA 2003/2008 deviation character checks (Eszett, Final Sigma, Joiners)
    fn has_deviation_characters(&self, label: &str) -> bool {
        for c in label.chars() {
            if c == 'ß' || c == 'ς' || c == '\u{200c}' || c == '\u{200d}' {
                return true;
            }
        }
        false
    }

    /// Checks for script confusable attacks based on TLD-specific allowances
    fn has_script_confusables(&self, label: &str, tld: &str) -> bool {
        self.check_confusable(label, tld, "Armenian", "ագզէլհյոսւօՙ", &["am"])
            || self.check_confusable(
                label,
                tld,
                "Cyrillic",
                "аысԁеԍһіюјӏорԗԛѕԝхуъьҽпгѵѡ",
                &["bg", "by", "kz", "ru", "su", "ua", "uz"],
            )
            || self.check_confusable(label, tld, "Greek", "αικνρυωηοτ", &["gr"])
            || self.check_confusable(label, tld, "Hebrew", "דוחיןסװײ׳ﬦ", &["il"])
            || self.check_confusable(label, tld, "Thai", "ทนบพรหเแ๐ดลปฟม", &["th"])
    }

    fn check_confusable(
        &self,
        label: &str,
        tld: &str,
        script_name: &str,
        lookalikes: &str,
        allowed_tlds: &[&str],
    ) -> bool {
        let mut script_chars = Vec::new();
        for c in label.chars() {
            if let Some(s) = self.get_char_script(c) {
                if s == script_name {
                    script_chars.push(c);
                }
            }
        }

        if script_chars.is_empty() {
            return false;
        }

        // Allowed ccTLDs bypass confusable alerts
        if allowed_tlds.contains(&tld) || tld == script_name.to_lowercase() {
            return false;
        }

        // If ALL character entries of this script are lookalikes
        script_chars.iter().all(|&c| lookalikes.contains(c))
    }

    /// Check script-specific restrictions (Icelandic, Azerbaijani, and non-ASCII Latin mixing)
    fn has_script_specific_spoofs(&self, label: &str, tld: &str) -> bool {
        if tld != "is" && (label.contains('þ') || label.contains('ð')) {
            return true;
        }

        if tld != "az" && label.contains('ə') {
            return true;
        }

        let mut scripts = HashSet::new();
        let mut has_non_ascii_latin = false;
        for c in label.chars() {
            if c == '-' || c.is_ascii_digit() {
                continue;
            }
            if let Some(script) = self.get_char_script(c) {
                scripts.insert(script);
                if script == "Latin" && !c.is_ascii() {
                    has_non_ascii_latin = true;
                }
            }
        }

        if scripts.len() > 1 && scripts.contains(&"Latin") && has_non_ascii_latin {
            return true;
        }

        false
    }

    fn get_char_script(&self, c: char) -> Option<&'static str> {
        let val = c as u32;
        match val {
            0x0000..=0x007F | 0x0080..=0x024F | 0x1E00..=0x1EFF => Some("Latin"),
            0x0400..=0x04FF | 0x0500..=0x052F | 0x2DE0..=0x2DFF | 0xA640..=0xA69F => {
                Some("Cyrillic")
            }
            0x0370..=0x03FF | 0x1F00..=0x1FFF => Some("Greek"),
            0x4E00..=0x9FFF | 0x3400..=0x4DBF => Some("Han"),
            0x3040..=0x309F => Some("Hiragana"),
            0x30A0..=0x30FF => Some("Katakana"),
            0x3100..=0x312F => Some("Bopomofo"),
            0xAC00..=0xD7AF | 0x1100..=0x11FF | 0x3130..=0x318F => Some("Hangul"),
            0x0530..=0x058F => Some("Armenian"),
            0x0590..=0x05FF => Some("Hebrew"),
            0x0E00..=0x0E7F => Some("Thai"),
            _ => None,
        }
    }

    fn is_cjk_char(&self, c: char) -> bool {
        if let Some(script) = self.get_char_script(c) {
            script == "Han"
                || script == "Hiragana"
                || script == "Katakana"
                || script == "Bopomofo"
                || script == "Hangul"
        } else {
            false
        }
    }

    fn is_dangerous_cjk_char(&self, c: char) -> bool {
        let val = c as u32;
        matches!(
            val,
            0x30CE
                | 0x30BD
                | 0x30BE
                | 0x30F3
                | 0x4E36
                | 0x4E40
                | 0x4E41
                | 0x4E3F
                | 0x4E00
                | 0x3127
                | 0x4E28
                | 0x4E5B
                | 0x4E03
                | 0x4E05
                | 0x5341
                | 0x3007
        )
    }

    /// Compliant Punycode (RFC 3492) Encoder
    fn punycode_encode(&self, input: &str) -> Option<String> {
        let mut output = String::new();
        let mut n = 128u32;
        let mut delta = 0u32;
        let mut bias = 72u32;

        let mut h = 0;
        for c in input.chars() {
            if c.is_ascii() {
                output.push(c);
                h += 1;
            }
        }

        let b = h;
        if b > 0 {
            output.push('-');
        }

        let remaining = input.chars().count();
        while h < remaining {
            let mut m = u32::MAX;
            for c in input.chars() {
                let val = c as u32;
                if val >= n && val < m {
                    m = val;
                }
            }

            delta = delta.checked_add((m - n).checked_mul(h as u32 + 1)?)?;
            n = m;

            for c in input.chars() {
                let val = c as u32;
                if val < n {
                    delta += 1;
                } else if val == n {
                    let mut q = delta;
                    let mut k = 36;
                    loop {
                        let t = if k <= bias {
                            1
                        } else if k >= bias + 26 {
                            26
                        } else {
                            k - bias
                        };
                        if q < t {
                            break;
                        }
                        let char_val = t + ((q - t) % (36 - t));
                        output.push(self.encode_digit(char_val)?);
                        q = (q - t) / (36 - t);
                        k += 36;
                    }
                    output.push(self.encode_digit(q)?);
                    bias = self.adapt(delta, h as u32 + 1, h == b);
                    delta = 0;
                    h += 1;
                }
            }
            delta += 1;
            n += 1;
        }
        Some(output)
    }

    fn encode_digit(&self, d: u32) -> Option<char> {
        if d < 26 {
            Some((d as u8 + b'a') as char)
        } else if d < 36 {
            Some((d as u8 - 26 + b'0') as char)
        } else {
            None
        }
    }

    fn adapt(&self, mut delta: u32, numpoints: u32, firsttime: bool) -> u32 {
        delta = if firsttime { delta / 700 } else { delta / 2 };
        delta += delta / numpoints;
        let mut k = 0;
        while delta > 36 * 26 / 2 {
            delta /= 35;
            k += 36;
        }
        k + (36 * delta) / (delta + 38)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idn_sanitizer_clean_domain() {
        let sanitizer = IDNSanitizer::new();
        let domain = "google.com";
        assert!(!sanitizer.detect_attack(domain));
        assert_eq!(sanitizer.sanitize(domain), "google.com");
    }

    #[test]
    fn test_idn_sanitizer_homograph_attack() {
        let sanitizer = IDNSanitizer::new();
        // 'е' here is Cyrillic Small Letter Ie (U+0435), not Latin 'e'
        let domain = "googlе.com";
        assert!(sanitizer.detect_attack(domain));
        let sanitized = sanitizer.sanitize(domain);
        assert!(sanitized.starts_with("xn--"));
    }

    #[test]
    fn test_idn_sanitizer_disallowed_characters() {
        let sanitizer = IDNSanitizer::new();
        // Contains zero-width space U+200B
        let domain = "google\u{200B}e.com";
        assert!(sanitizer.detect_attack(domain));
    }

    #[test]
    fn test_idn_sanitizer_dangerous_patterns() {
        let sanitizer = IDNSanitizer::new();
        // CJK ideograph U+4E00 next to Latin characters
        let domain = "google一.com";
        assert!(sanitizer.detect_attack(domain));
    }

    #[test]
    fn test_idn_sanitizer_deviation_characters() {
        let sanitizer = IDNSanitizer::new();
        let domain = "fass.de"; // normal German
        assert!(!sanitizer.detect_attack(domain));

        let domain_sz = "faß.de"; // German Eszett deviation
        assert!(sanizer_detects_deviation(domain_sz));
    }

    fn sanizer_detects_deviation(domain: &str) -> bool {
        let sanitizer = IDNSanitizer::new();
        sanitizer.detect_attack(domain)
    }

    #[test]
    fn test_idn_sanitizer_script_confusable() {
        let sanitizer = IDNSanitizer::new();
        // Cyrillic lookalike domain
        let domain = "рaypal.com"; // 'р' is Cyrillic Small Letter Er (U+0440)
        assert!(sanitizer.detect_attack(domain));
    }

    #[test]
    fn test_idn_sanitizer_script_specific() {
        let sanitizer = IDNSanitizer::new();
        // Icelandic characters allowed ONLY under .is
        let clean_is = "þing.is";
        assert!(!sanitizer.detect_attack(clean_is));

        let dirty_com = "þing.com";
        assert!(sanitizer.detect_attack(dirty_com));
    }
}
