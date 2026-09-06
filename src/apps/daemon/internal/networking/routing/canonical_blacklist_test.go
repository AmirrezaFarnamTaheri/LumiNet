package routing

import (
	"testing"
)

func TestCanonicalBlacklistEngine(t *testing.T) {
	engine := NewCanonicalBlacklistEngine()
	engine.ParseRawRule("||wikipedia.org")
	engine.ParseRawRule("|https://allowed.wikipedia.org")
	engine.ParseRawRule("@@||allowed.wikipedia.org")
	engine.ParseRawRule("censor-word")

	res, rule := engine.EvaluateTarget("en.wikipedia.org")
	if res != MatchBlocked || rule != "wikipedia.org" {
		t.Fatalf("expected blocked by wikipedia.org, got %v (%s)", res, rule)
	}

	res, rule = engine.EvaluateTarget("allowed.wikipedia.org")
	if res != MatchWhitelisted {
		t.Fatalf("expected whitelisted, got %v (%s)", res, rule)
	}

	res, rule = engine.EvaluateTarget("news-censor-word-portal.com")
	if res != MatchBlocked || rule != "censor-word" {
		t.Fatalf("expected keyword blocked, got %v (%s)", res, rule)
	}

	res, _ = engine.EvaluateTarget("goodsite.org")
	if res != MatchDirect {
		t.Fatalf("expected direct, got %v", res)
	}
}
