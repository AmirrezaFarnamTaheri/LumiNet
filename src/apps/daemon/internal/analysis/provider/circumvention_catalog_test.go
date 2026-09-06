package provider

import "testing"

func TestCircumventionCatalogHasUniqueIDsAndDefensiveTags(t *testing.T) {
	got := CircumventionCatalog()
	if len(got) < 15 {
		t.Fatalf("catalog too small: %d", len(got))
	}
	seen := map[string]struct{}{}
	for _, item := range got {
		if item.ID == "" || item.Name == "" || item.Category == "" || item.Integration == "" || item.Description == "" {
			t.Fatalf("incomplete item: %+v", item)
		}
		if _, ok := seen[item.ID]; ok {
			t.Fatalf("duplicate id %q", item.ID)
		}
		seen[item.ID] = struct{}{}
	}
	if len(got[0].Tags) == 0 {
		t.Fatal("fixture has no tags")
	}
	first := got[0].Tags[0]
	got[0].Tags[0] = "mutated"
	if CircumventionCatalog()[0].Tags[0] != first {
		t.Fatal("catalog leaked mutable tags")
	}
}
