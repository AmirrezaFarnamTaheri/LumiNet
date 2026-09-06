// tor_vanguards_test.go — characterization tests for the vanguards port.
//
// All thresholds and counts are taken directly from the upstream Python
// (vanguards-master, MIT, U.S. Naval Research Laboratory). Tests assert
// the boundary cases the daemon care about: route-len deviation, layer
// membership, rendezvous over-use, and CBT timeout rate.
package system

import (
	"math"
	"testing"
)

func TestRouteLenForPurpose_FullVanguards(t *testing.T) {
	cases := map[string]int{
		"HS_VANGUARDS":     4,
		"HS_CLIENT_HSDIR":  5,
		"HS_CLIENT_INTRO":  5,
		"HS_CLIENT_REND":   4,
		"HS_SERVICE_HSDIR": 4,
		"HS_SERVICE_INTRO": 4,
		"HS_SERVICE_REND":  5,
	}
	for purpose, want := range cases {
		got, ok := RouteLenForPurpose(purpose, false)
		if !ok || got != want {
			t.Errorf("full RouteLenForPurpose(%q) = %d,%v want %d,true", purpose, got, ok, want)
		}
	}
}

func TestRouteLenForPurpose_VanguardsLite(t *testing.T) {
	cases := map[string]int{
		"HS_VANGUARDS":     3,
		"HS_CLIENT_HSDIR":  4,
		"HS_CLIENT_INTRO":  4,
		"HS_CLIENT_REND":   3,
		"HS_SERVICE_HSDIR": 4,
		"HS_SERVICE_INTRO": 4,
		"HS_SERVICE_REND":  4,
	}
	for purpose, want := range cases {
		got, ok := RouteLenForPurpose(purpose, true)
		if !ok || got != want {
			t.Errorf("lite RouteLenForPurpose(%q) = %d,%v want %d,true", purpose, got, ok, want)
		}
	}
}

func TestRouteLenForPurpose_Unknown(t *testing.T) {
	if got, ok := RouteLenForPurpose("NONSENSE", false); ok || got != 0 {
		t.Errorf("expected unknown, got %d,%v", got, ok)
	}
}

func TestParseCircuitPurpose(t *testing.T) {
	cases := map[string]CircuitPurpose{
		"HS_CLIENT_HSDIR":   PurposeHSClientHSDir,
		"HS_CLIENT_INTRO":   PurposeHSClientIntro,
		"HS_CLIENT_REND":    PurposeHSClientRend,
		"HS_SERVICE_HSDIR":  PurposeHSServiceHSDir,
		"HS_SERVICE_INTRO":  PurposeHSServiceIntro,
		"HS_SERVICE_REND":   PurposeHSServiceRend,
		"HS_VANGUARDS":      PurposeHSVanguards,
		"GENERAL":           PurposeUnknown,
		"HS_CLIENT_FOO_BAR": PurposeUnknown,
	}
	for s, want := range cases {
		if got := ParseCircuitPurpose(s); got != want {
			t.Errorf("ParseCircuitPurpose(%q) = %v want %v", s, got, want)
		}
	}
}

func TestLayer1Guards_AddDelConn(t *testing.T) {
	g := NewLayer1Guards(2)
	g.AddConn("AAAA")
	g.AddConn("AAAA")
	g.AddConn("BBBB")
	if v := g.CheckConnCounts(); v.Count != 2 || v.Status != "correct" || len(v.Extra) != 1 {
		t.Errorf("want 2 distinct, correct, 1 extra, got %+v", v)
	}
	g.DelConn("AAAA")
	if v := g.CheckConnCounts(); v.Count != 2 {
		// Still 2 because AAAA had ConnCount=2.
		t.Errorf("want Count==2 after single Dec, got %+v", v)
	}
	g.DelConn("AAAA")
	if v := g.CheckConnCounts(); v.Count != 1 || v.Status != "fewer" {
		t.Errorf("want 1,fewer, got %+v", v)
	}
}

func TestLayer1Guards_UseCounts(t *testing.T) {
	g := NewLayer1Guards(2)
	g.AddConn("AAAA")
	g.AddConn("BBBB")
	g.AddUseCount("AAAA")
	g.AddUseCount("AAAA")
	g.AddUseCount("BBBB")
	v := g.CheckUseCounts()
	if v.InUse != 2 || v.Status != "correct" {
		t.Errorf("want 2 in use, correct, got %+v", v)
	}
	if v.Counts["AAAA"] != 2 || v.Counts["BBBB"] != 1 {
		t.Errorf("want counts 2/1, got %+v", v.Counts)
	}
}

func TestGuardSet_ApplyReplace(t *testing.T) {
	gs := NewGuardSet()
	if !gs.Apply(GuardEventGoodL2, "FP1") {
		t.Error("first GoodL2 should change")
	}
	if gs.Apply(GuardEventGoodL2, "FP1") {
		t.Error("second GoodL2 should be a no-op")
	}
	gs.Apply(GuardEventGoodL2, "FP2")
	if got := gs.Members(); len(got) != 2 || got[0] != "FP1" || got[1] != "FP2" {
		t.Errorf("Members() = %v want [FP1 FP2]", got)
	}
	gs.Apply(GuardEventBadL2, "FP1")
	if !gs.Contains("FP2") || gs.Contains("FP1") {
		t.Errorf("after demote FP1: contains FP1=%v FP2=%v", gs.Contains("FP1"), gs.Contains("FP2"))
	}
	gs.Replace([]string{"X", "Y", "Z"})
	if gs.Size() != 3 || !gs.Contains("X") {
		t.Errorf("Replace failed: %v", gs.Members())
	}
	// Empty strings must be dropped.
	gs.Replace([]string{"", "A", ""})
	if gs.Size() != 1 {
		t.Errorf("empty strings must be dropped, got %d", gs.Size())
	}
}

func TestPathVerify_CircEvent_LayerMembership(t *testing.T) {
	pv := NewPathVerify(PathVerifyConfig{
		Vanguards: VanguardsConfig{
			FullVanguards: true,
			NumLayer1:     1,
			NumLayer2:     4,
			NumLayer3:     2,
		},
	})
	pv.Layer1().AddConn("G1")
	pv.SetLayers([]string{"L2A", "L2B", "L2C", "L2D"}, []string{"L3A", "L3B"})

	// Healthy HS_CLIENT_REND circuit: 4 hops, all in the right layers.
	good := pv.CircEvent(PurposeHSClientRend, [][2]string{
		{"G1", "guard1"},
		{"L2A", "l2a"},
		{"L3A", "l3a"},
		{"RP", "rend"},
	}, "")
	if !good.RouteLenOK || !good.Layer1OK || !good.Layer2OK || !good.Layer3OK {
		t.Errorf("healthy circuit should be OK, got %+v", good)
	}

	// Wrong route length, non-cannibalized: not OK.
	bad := pv.CircEvent(PurposeHSClientRend, [][2]string{
		{"G1", "guard1"},
		{"L2A", "l2a"},
		{"RP", "rend"},
	}, "")
	if bad.RouteLenOK {
		t.Errorf("short path should not be OK, got %+v", bad)
	}

	// Wrong route length but cannibalized: treated as OK (INFO, not WARN).
	can := pv.CircEvent(PurposeHSServiceHSDir, [][2]string{
		{"G1", "guard1"},
		{"L2A", "l2a"},
		{"L3A", "l3a"},
	}, "HSSI_CONNECTING")
	if !can.RouteLenOK || !can.Cannibalized {
		t.Errorf("cannibalized should be OK and flagged, got %+v", can)
	}

	// Layer-1 not in set: Layer1OK false, but circuit still recorded.
	noGuard := pv.CircEvent(PurposeHSClientRend, [][2]string{
		{"G_NOT_KNOWN", "ghost"},
		{"L2A", "l2a"},
		{"L3A", "l3a"},
		{"RP", "rend"},
	}, "")
	if noGuard.Layer1OK {
		t.Errorf("unknown guard should not be OK, got %+v", noGuard)
	}
}

func TestPathVerify_NonHSPurposeSkipped(t *testing.T) {
	pv := NewPathVerify(PathVerifyConfig{
		Vanguards: VanguardsConfig{FullVanguards: false, NumLayer1: 1, NumLayer2: 4, NumLayer3: 0},
	})
	res := pv.CircEvent(PurposeUnknown, [][2]string{{"X", "x"}}, "")
	if res.RouteLenExpected != 0 || res.RouteLenActual != 0 {
		t.Errorf("non-HS circuit should be skipped, got %+v", res)
	}
}

func TestRendGuard_ThresholdTrigger(t *testing.T) {
	cfg := RendGuardConfig{
		GlobalStartCount: 100, // lowered to keep the test fast.
		RelayStartCount:  10,
		MaxUseToBWRatio:  5.0,
	}
	g := NewRendGuard(cfg)
	// 100 uses total, relay A has 90 of them, weight 0.1 ⇒ ratio = 90/(0.1*100) = 9 > 5.
	for i := 0; i < 100; i++ {
		var fp string
		var w float64
		if i < 90 {
			fp, w = "A", 0.1
		} else {
			fp, w = "B", 0.1
		}
		g.RecordUse(fp, w)
	}
	// Drive over the threshold with a few more events so A crosses
	// RelayStartCount + GlobalStartCount combined test invariants.
	over := g.RecordUse("A", 0.1)
	if !over {
		t.Error("expected overuse trigger on A")
	}
	if g.LastOveruse() != "A" {
		t.Errorf("lastOveruse = %q want A", g.LastOveruse())
	}
	// A relay that nobody overused should not trigger.
	if g.RecordUse("C", 0.0001) {
		// C weight is tiny but Used=1 < RelayStartCount ⇒ no trigger.
		t.Error("low-use relay should not trigger over-use")
	}
}

func TestRendGuard_BelowGlobalStartCount_NoTrigger(t *testing.T) {
	cfg := RendGuardConfig{
		GlobalStartCount: 1000,
		RelayStartCount:  5,
		MaxUseToBWRatio:  5.0,
	}
	g := NewRendGuard(cfg)
	for i := 0; i < 50; i++ {
		g.RecordUse("A", 0.0001)
	}
	if g.LastOveruse() != "" {
		t.Errorf("below GlobalStartCount must not trigger, got %q", g.LastOveruse())
	}
}

func TestCBTStats_Counters(t *testing.T) {
	s := NewCBTStats()
	s.CircEvent("c1", "LAUNCHED", "", true)
	s.CircEvent("c1", "BUILT", "", true)
	s.CircEvent("c2", "LAUNCHED", "", true)
	s.CircEvent("c2", "", "TIMEOUT", true)
	s.CircEvent("c3", "LAUNCHED", "", false)
	s.CircEvent("c3", "", "TIMEOUT", false)
	s.CircEvent("c3", "FAILED", "", false)
	snap := s.Snapshot()
	if snap.HSLaunched != 2 || snap.HSBuilt != 1 || snap.HSTimeout != 1 {
		t.Errorf("HS counters wrong: %+v", &snap)
	}
	if snap.AllLaunched != 1 || snap.AllTimeout != 1 {
		t.Errorf("all counters wrong: %+v", &snap)
	}
	if got := s.TimeoutRate(); math.Abs(got-0.5) > 1e-9 {
		t.Errorf("TimeoutRate = %f want 0.5", got)
	}
}

func TestCBTStats_TimeoutRate_Empty(t *testing.T) {
	s := NewCBTStats()
	if got := s.TimeoutRate(); got != 0 {
		t.Errorf("empty TimeoutRate = %f want 0", got)
	}
}
