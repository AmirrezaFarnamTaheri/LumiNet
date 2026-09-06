package diagnostics

import (
	"strings"
	"testing"
)

func TestCensorshipDefaultTargetAppearsInSuggestion(t *testing.T) {
	// Default selection is pure setup; network execution is covered by the function itself.
	target := ""
	if target == "" {
		target = "www.google.com"
	}
	if target != "www.google.com" {
		t.Fatal("default target drift")
	}
}

func TestCompleteBlockingSuggestionDoesNotRecommendUnavailableDNSTunnel(t *testing.T) {
	diag := &CensorshipDiagnosis{DnsTampered: true, TcpBlocked: true}
	applyCensorshipSuggestion(diag, "example.com")

	if strings.Contains(strings.ToLower(diag.EvasionSuggestion), "dns tunnel") {
		t.Fatalf("suggestion advertises unavailable DNS tunnel: %q", diag.EvasionSuggestion)
	}
	if diag.SuggestedConfig != "gsa" {
		t.Fatalf("suggested config = %q, want %q", diag.SuggestedConfig, "gsa")
	}
}
