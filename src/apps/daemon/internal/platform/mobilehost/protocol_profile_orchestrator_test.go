package mobilehost

import (
	"testing"
)

func TestProtocolProfileOrchestrator(t *testing.T) {
	orch := NewProtocolProfileOrchestrator()

	p1 := ProfileContainer{
		ProfileID:      "prof-awg",
		Name:           "Amnezia WireGuard Primary",
		Protocol:       ProtoAmneziaWg,
		ServerEndpoint: "198.51.100.10:51820",
		FallbackOrder:  1,
		ConfigPayload:  "awg://...",
	}
	p2 := ProfileContainer{
		ProfileID:      "prof-masque",
		Name:           "MASQUE Datagram Fallback",
		Protocol:       ProtoMasque,
		ServerEndpoint: "198.51.100.11:443",
		FallbackOrder:  2,
		ConfigPayload:  "masque://...",
	}

	orch.AddProfile(p1)
	orch.AddProfile(p2)

	active, err := orch.GetActiveProfile()
	if err != nil {
		t.Fatalf("failed to get active profile: %v", err)
	}
	if active.ProfileID != "prof-awg" {
		t.Fatalf("expected prof-awg active, got %s", active.ProfileID)
	}

	chain := orch.GetFallbackChain()
	if len(chain) != 2 {
		t.Fatalf("expected 2 in fallback chain, got %d", len(chain))
	}
	if chain[0].ProfileID != "prof-awg" || chain[1].ProfileID != "prof-masque" {
		t.Fatalf("fallback ordering incorrect")
	}

	// Switch active
	if err := orch.SetActiveProfile("prof-masque"); err != nil {
		t.Fatalf("failed to switch active profile: %v", err)
	}
	active2, _ := orch.GetActiveProfile()
	if active2.ProfileID != "prof-masque" {
		t.Fatalf("expected active to be prof-masque")
	}

	// Export / Import JSON roundtrip
	jsonData, err := orch.ExportProfilesJSON()
	if err != nil {
		t.Fatalf("export JSON failed: %v", err)
	}

	orch2 := NewProtocolProfileOrchestrator()
	if err := orch2.ImportProfilesJSON(jsonData); err != nil {
		t.Fatalf("import JSON failed: %v", err)
	}
	if len(orch2.GetFallbackChain()) != 2 {
		t.Fatalf("expected 2 imported profiles")
	}
}
