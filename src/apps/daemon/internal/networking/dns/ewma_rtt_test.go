package dns

import (
	"testing"
	"time"
)

func TestEWMARtt_FirstSampleSeeds(t *testing.T) {
	t.Parallel()
	e := NewEWMARtt(0.125)
	if e.Initialized() {
		t.Fatal("fresh EWMARtt should not be initialised")
	}
	if e.Smoothed() != 0 {
		t.Fatalf("expected zero Smoothed before any sample, got %v", e.Smoothed())
	}
	e.Observe(100 * time.Millisecond)
	if !e.Initialized() {
		t.Fatal("EWMARtt should be initialised after first sample")
	}
	if got := e.Smoothed(); got != 100*time.Millisecond {
		t.Fatalf("first sample must seed SRTT, got %v", got)
	}
}

func TestEWMARtt_Smoothing(t *testing.T) {
	t.Parallel()
	e := NewEWMARtt(0.5) // heavy smoothing for predictable test
	e.Observe(100 * time.Millisecond)
	e.Observe(200 * time.Millisecond)
	// SRTT after two samples with alpha=0.5: (1-0.5)*100 + 0.5*200 = 150
	if got := e.Smoothed(); got != 150*time.Millisecond {
		t.Fatalf("expected 150ms after second sample, got %v", got)
	}
	e.Observe(200 * time.Millisecond)
	// (1-0.5)*150 + 0.5*200 = 175
	if got := e.Smoothed(); got != 175*time.Millisecond {
		t.Fatalf("expected 175ms after third sample, got %v", got)
	}
}

func TestEWMARtt_RTOAtLeastSmoothed(t *testing.T) {
	t.Parallel()
	e := NewEWMARtt(0.125)
	e.Observe(50 * time.Millisecond)
	rto := e.RTO()
	if rto < e.Smoothed() {
		t.Fatalf("RTO %v must be >= SRTT %v", rto, e.Smoothed())
	}
}

func TestEWMARtt_RejectsInvalidAlpha(t *testing.T) {
	t.Parallel()
	for _, alpha := range []float64{-1, 0, 1.5, 999} {
		e := NewEWMARtt(alpha)
		if e.alpha != 0.125 {
			t.Errorf("invalid alpha %v should fall back to 0.125, got %v", alpha, e.alpha)
		}
	}
}

func TestEWMARtt_Reset(t *testing.T) {
	t.Parallel()
	e := NewEWMARtt(0.125)
	e.Observe(100 * time.Millisecond)
	e.Reset()
	if e.Initialized() {
		t.Fatal("Reset should clear initialised state")
	}
	if e.Smoothed() != 0 {
		t.Fatal("Reset should clear SRTT")
	}
}

func TestEWMARtt_NegativeSampleIgnored(t *testing.T) {
	t.Parallel()
	e := NewEWMARtt(0.125)
	e.Observe(50 * time.Millisecond)
	e.Observe(-1 * time.Millisecond) // should be ignored
	if got := e.Smoothed(); got != 50*time.Millisecond {
		t.Fatalf("negative sample must be ignored, got %v", got)
	}
}

func TestEWMARttRegistry_PerUpstreamState(t *testing.T) {
	t.Parallel()
	reg := NewEWMARttRegistry(0.125)
	a := reg.For("a")
	b := reg.For("b")
	a.Observe(10 * time.Millisecond)
	b.Observe(1000 * time.Millisecond)
	if a.Smoothed() != 10*time.Millisecond {
		t.Errorf("a SRTT = %v, want 10ms", a.Smoothed())
	}
	if b.Smoothed() != 1000*time.Millisecond {
		t.Errorf("b SRTT = %v, want 1000ms", b.Smoothed())
	}
	// Same id returns the same tracker.
	if reg.For("a") != a {
		t.Error("For must return the same tracker for the same id")
	}
}

func TestEWMARttRegistry_Forget(t *testing.T) {
	t.Parallel()
	reg := NewEWMARttRegistry(0.125)
	reg.For("x").Observe(50 * time.Millisecond)
	reg.Forget("x")
	if ids := reg.IDs(); len(ids) != 0 {
		t.Errorf("expected empty registry after Forget, got %v", ids)
	}
}

func TestEWMARttRegistry_IDs(t *testing.T) {
	t.Parallel()
	reg := NewEWMARttRegistry(0.125)
	reg.For("a")
	reg.For("b")
	reg.For("c")
	ids := reg.IDs()
	if len(ids) != 3 {
		t.Errorf("expected 3 ids, got %d (%v)", len(ids), ids)
	}
}
