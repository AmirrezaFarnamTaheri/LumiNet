package diagnostics

import (
	"strings"
	"testing"
)

func TestCuratedSniCandidatesAreValidUniqueAndDefensiveCopy(t *testing.T) {
	got := CuratedSniCandidates()
	if len(got) != 285 {
		t.Fatalf("candidate count=%d, want 285", len(got))
	}
	seen := make(map[string]struct{}, len(got))
	for _, candidate := range got {
		if !validSNI(candidate) {
			t.Fatalf("invalid candidate %q", candidate)
		}
		key := strings.ToLower(candidate)
		if _, ok := seen[key]; ok {
			t.Fatalf("duplicate candidate %q", candidate)
		}
		seen[key] = struct{}{}
	}
	first := got[0]
	got[0] = "mutated.example"
	if CuratedSniCandidates()[0] != first {
		t.Fatal("candidate corpus leaked mutable backing storage")
	}
}
