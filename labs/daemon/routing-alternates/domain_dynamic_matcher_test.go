package routing

import "testing"

func TestDynamicMatcherPreservesHistoricalOverrideSemantics(t *testing.T) {
	matcher := NewDynamicMatcher()
	matcher.AddBlockedDomain("Blocked.Example")
	matcher.AddDirectDomain("direct.example")

	tests := []struct {
		domain string
		want   string
	}{
		{"blocked.example", "proxy"},
		{"www.blocked.example", "proxy"},
		{"DIRECT.EXAMPLE", "direct"},
		{"api.direct.example", "direct"},
		{"notblocked.example", "default"},
		{"example.org", "default"},
	}
	for _, test := range tests {
		if got := matcher.MatchDomain(test.domain); got != test.want {
			t.Fatalf("MatchDomain(%q) = %q, want %q", test.domain, got, test.want)
		}
	}
}

func TestDynamicMatcherBlockedOverridesDirect(t *testing.T) {
	matcher := NewDynamicMatcher()
	matcher.AddDirectDomain("example.com")
	matcher.AddBlockedDomain("example.com")
	if got := matcher.MatchDomain("example.com"); got != "proxy" {
		t.Fatalf("MatchDomain() = %q, want proxy", got)
	}
}
