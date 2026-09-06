package routing

import (
	"testing"
)

func TestAutoProxyMatcher(t *testing.T) {
	matcher := NewAutoProxyMatcher()
	matcher.ParseLine("@@||cn.bing.com")
	matcher.ParseLine("||youtube.com")

	if v, ok := matcher.Match("https://cn.bing.com"); !ok || v != VerdictDirect {
		t.Errorf("expected cn.bing.com to match DIRECT")
	}
	if v, ok := matcher.Match("https://www.youtube.com/watch"); !ok || v != VerdictProxy {
		t.Errorf("expected youtube.com to match PROXY")
	}
	if _, ok := matcher.Match("https://unmatched.org"); ok {
		t.Errorf("expected unmatched.org not to match")
	}
}
