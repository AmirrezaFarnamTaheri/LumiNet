package diagnostics

import (
	"testing"
)

func TestDohFallback(t *testing.T) {
	h := NewDohFallbackHierarchy()
	active := h.SelectActive()
	if active == nil || active.Tier != 1 {
		t.Fatalf("expected Tier 1 active endpoint")
	}

	firstUrl := active.URL
	h.RecordFailure(firstUrl)
	h.RecordFailure(firstUrl)
	h.RecordFailure(firstUrl)

	next := h.SelectActive()
	if next.URL == firstUrl {
		t.Errorf("expected failover away from failed endpoint")
	}
}
