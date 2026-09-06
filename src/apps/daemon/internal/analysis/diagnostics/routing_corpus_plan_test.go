package diagnostics

import "testing"

func TestPostRefactor224RoutingCorpusAuditIsProvenanceOnly(t *testing.T) {
	p, err := BuildRoutingCorpusPlan([]RoutingCorpusFile{{Name: "security", Includes: []string{"domestic", "missing"}, Rules: []RoutingCorpusRule{{Action: "block", Value: "bad.example"}, {Action: "block", Value: "bad.example"}}}, {Name: "domestic", Rules: []RoutingCorpusRule{{Action: "direct", Value: "ir"}, {Action: "bogus", Value: "x"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if p.ImportsMutableDatasets || p.MissingIncludes != 1 || p.InvalidRules != 1 || p.DuplicateRules < 1 || p.CombinedSHA256 == "" {
		t.Fatalf("plan=%+v", p)
	}
	if len(p.ActionProvenance["block"]) != 1 || len(p.ActionProvenance["direct"]) != 1 {
		t.Fatalf("provenance=%+v", p.ActionProvenance)
	}
}
func TestPostRefactor224RoutingPolicyPresetsAreStableAndDatasetFree(t *testing.T) {
	p := RoutingPolicyPresets()
	if len(p) != 3 || p[0].ID != "balanced-security" || p[1].ID != "security-first" || p[2].ID != "minimal-direct" {
		t.Fatalf("presets=%+v", p)
	}
}
