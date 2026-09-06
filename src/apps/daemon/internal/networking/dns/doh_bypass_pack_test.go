package dns

import (
	"sort"
	"testing"
)

func TestLoadDoHBypassPack(t *testing.T) {
	domains, skipped := LoadDoHBypassPack()
	if len(domains) == 0 {
		t.Fatal("expected embedded pack to yield domains")
	}
	if !sort.StringsAreSorted(domains) {
		t.Fatal("domains not sorted")
	}
	// Uniqueness: sorted + deduped means no adjacent duplicates.
	for i := 1; i < len(domains); i++ {
		if domains[i] == domains[i-1] {
			t.Fatalf("duplicate domain %q", domains[i])
		}
	}
	// Comments must not leak in as entries.
	for _, d := range domains {
		if len(d) == 0 || d[0] == '#' {
			t.Fatalf("invalid entry %q", d)
		}
	}
	t.Logf("pack loaded: %d domains, %d duplicates skipped", len(domains), skipped)
}
