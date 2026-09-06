// SPDX-License-Identifier: MIT
//
// Homoglyph / confusable-character detection (roadmap item 8; design
// are attacker-influenced input; a hostname like "gооgle.com" (Cyrillic
// о) dialled verbatim silently reroutes traffic. Hostnames reaching the
// daemon must be ASCII A-labels (IDN is punycode), so any non-ASCII
// letter inside a hostname is structurally suspicious — we detect and
// fold them so callers can reject or report before dialling.
//
// The skeleton algorithm is a simplified UTN #47: lowercase, fold known
// confusables to ASCII, strip separators. Two visually identical strings
// share a skeleton; a skeleton differing from the raw form proves the
// raw form contained confusables.

package textconfusables

import (
	"net/url"
	"strings"
)

// confusables maps common homoglyph codepoints (Cyrillic, Greek, and
// fullwidth forms) to their ASCII lookalikes.
var confusables = map[rune]rune{
	// Cyrillic
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
	'х': 'x', 'у': 'y', 'к': 'k', 'м': 'm', 'т': 't',
	'в': 'b', 'н': 'h', 'і': 'i', 'ѕ': 's', 'џ': 'j',
	'ԁ': 'd', 'ɡ': 'g', 'һ': 'h', 'ј': 'j', 'ӏ': 'i',
	'Ӏ': 'i', 'ç': 'c', 'ԛ': 'q', 'ԝ': 'w',
	// Greek
	'ο': 'o', 'α': 'a', 'ε': 'e', 'ρ': 'p', 'ν': 'v',
	'ι': 'i', 'κ': 'k', 'τ': 't', 'υ': 'u', 'χ': 'x',
	'Α': 'a', 'Β': 'b', 'Ε': 'e', 'Ζ': 'z', 'Η': 'h',
	'Κ': 'k', 'Μ': 'm', 'Ν': 'n', 'Ο': 'o', 'Ρ': 'p',
	'Τ': 't', 'Υ': 'y', 'Χ': 'x',
	// Fullwidth Latin
	'０': '0', '１': '1', '２': '2', '３': '3', '４': '4',
	'５': '5', '６': '6', '７': '7', '８': '8', '９': '9',
}

// ConfusableRunes returns every rune in s that is a known confusable,
// in order of appearance. Empty for pure-ASCII input.
func ConfusableRunes(s string) []rune {
	var found []rune
	for _, r := range s {
		if _, ok := confusables[r]; ok {
			found = append(found, r)
		}
	}
	return found
}

// HasConfusables reports whether s contains any known homoglyphs.
func HasConfusables(s string) bool {
	return len(ConfusableRunes(s)) > 0
}

// Skeleton folds s to its comparison form: NLC-lowercased, confusables
// folded to ASCII, separators (. - _ space) removed. Visual twins share
// a skeleton.
func Skeleton(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch r {
		case '.', '-', '_', ' ':
			continue
		}
		if ascii, ok := confusables[r]; ok {
			r = ascii
		}
		b.WriteRune(r)
	}
	return b.String()
}

// SuspiciousHostname reports whether a hostname should be rejected as a
// homograph risk: it contains non-ASCII letters (real hostnames are
// ASCII/punycode A-labels) or known confusables inside an otherwise
// ASCII name. The second return describes the first finding.
func SuspiciousHostname(host string) (bool, string) {
	if host == "" {
		return false, ""
	}
	for _, r := range host {
		if r > 127 && !strings.ContainsRune("._-", r) {
			return true, "non-ASCII rune in hostname"
		}
	}
	if runes := ConfusableRunes(host); len(runes) > 0 {
		return true, "confusable rune in ASCII-looking hostname"
	}
	return false, ""
}

// SuspiciousURL extracts the hostname from a URL and applies
// SuspiciousHostname to it. Malformed URLs are reported as suspicious
// (callers treat subscription entries they cannot parse as unsafe).
func SuspiciousURL(raw string) (bool, string) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return true, "unparseable URL or missing host"
	}
	return SuspiciousHostname(u.Hostname())
}
