package diagnostics

import "testing"

func TestPostRefactor224TrafficProfileAnalysisAndPresets(t *testing.T) {
	p, err := BuildTrafficProfilePlan(TrafficProfileRequest{Version: "1", Entry: "start", States: []TrafficProfileState{
		{ID: "start", Actions: []TrafficProfileAction{{Kind: "delay", DelayMs: 20}, {Kind: "padding", PaddingBytes: 128, Async: true}}, Transitions: []TrafficProfileTransition{{To: "work", Probability: 1}}},
		{ID: "work", Actions: []TrafficProfileAction{{Kind: "burst", BurstBytes: 4096, OverheadPercent: 10, TimeoutMs: 1000}}, Transitions: []TrafficProfileTransition{{To: "work", Probability: .2}, {To: "done", Probability: .8}, {To: "failed", OnError: true}}},
		{ID: "done", Terminal: true}, {ID: "failed", Terminal: true}, {ID: "unused", Terminal: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.DeclarativeOnly || p.ExecutesPlugins || !p.Cyclic || len(p.UnreachableStates) != 1 || p.UnreachableStates[0] != "unused" {
		t.Fatalf("plan=%+v", p)
	}
	if len(TrafficBehaviorPresets()) != 4 {
		t.Fatal("expected four bounded presets")
	}
}
func TestPostRefactor224TrafficProfileRejectsExecutableAction(t *testing.T) {
	_, err := BuildTrafficProfilePlan(TrafficProfileRequest{Version: "1", Entry: "a", States: []TrafficProfileState{{ID: "a", Actions: []TrafficProfileAction{{Kind: "exec"}}, Terminal: true}}})
	if err == nil {
		t.Fatal("expected executable action rejection")
	}
}

func TestPostRefactor224TrafficBehaviorPresetsStayDeclarativeAndBounded(t *testing.T) {
	presets := TrafficBehaviorPresets()
	if len(presets) != 4 {
		t.Fatalf("preset count=%d", len(presets))
	}
	seen := map[string]bool{}
	for _, p := range presets {
		if p.ID == "" || seen[p.ID] {
			t.Fatalf("invalid/duplicate preset id %q", p.ID)
		}
		seen[p.ID] = true
		if p.DelayMs < 0 || p.DelayMs > 60000 || p.PaddingBytes < 0 || p.PaddingBytes > 64<<10 || p.BurstBytes < 0 || p.BurstBytes > 1<<20 || p.OverheadPercent < 0 || p.OverheadPercent > 100 {
			t.Fatalf("preset exceeds declarative bounds: %+v", p)
		}
	}
}
