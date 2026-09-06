package textconfusables

import "testing"

func TestConfusablesDetection(t *testing.T) {
	// Cyrillic о inside an ASCII-looking name.
	if !HasConfusables("gооgle.com") {
		t.Fatal("cyrillic-о homoglyph not detected")
	}
	if HasConfusables("google.com") {
		t.Fatal("false positive on pure ASCII")
	}
	runes := ConfusableRunes("gооgle.com")
	if len(runes) != 2 {
		t.Fatalf("runes = %d, want 2", len(runes))
	}
}

func TestSkeletonTwinsMatch(t *testing.T) {
	// Visually identical: ASCII vs Cyrillic-folded.
	if Skeleton("gооgle.com") != Skeleton("google.com") {
		t.Fatalf("twins diverge: %q vs %q", Skeleton("gооgle.com"), Skeleton("google.com"))
	}
	// Separators are stripped.
	if Skeleton("my-app.example.com") != Skeleton("myappexamplecom") {
		t.Fatal("separator stripping diverged")
	}
}

func TestSuspiciousHostname(t *testing.T) {
	cases := []struct {
		host    string
		want    bool
		because string
	}{
		{"google.com", false, ""},
		{"xn--e1afmkfd.xn--p1ai", false, ""}, // punycode A-label is legitimate
		{"gооgle.com", true, "confusable rune in ASCII-looking hostname"},
		{"exаmple.com", true, "confusable rune in ASCII-looking hostname"},
		{"пример.рф", true, "non-ASCII rune in hostname"},
		{"", false, ""},
	}
	for _, c := range cases {
		got, why := SuspiciousHostname(c.host)
		if got != c.want {
			t.Errorf("SuspiciousHostname(%q) = %v (%q), want %v", c.host, got, why, c.want)
		}
	}
}

func TestSuspiciousURL(t *testing.T) {
	if got, _ := SuspiciousURL("https://gооgle.com/x"); !got {
		t.Fatal("homoglyph URL host not flagged")
	}
	if got, _ := SuspiciousURL("https://sub.clean.example.com:8443/path"); got {
		t.Fatal("clean URL flagged")
	}
	// No host at all → flagged.
	if got, why := SuspiciousURL("not a url"); !got {
		t.Fatalf("hostless input should be flagged, why=%q", why)
	}
}
