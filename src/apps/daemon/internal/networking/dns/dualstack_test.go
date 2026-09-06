// Copyright 2024 LumiNet. Use of this source code is governed by the MIT license.

package dns

import (
	"strings"
	"testing"
	"time"
)

type staticProbe bool

func (s staticProbe) IPv6Ready() bool { return bool(s) }

func TestDualstackCounterpartQtype(t *testing.T) {
	if got := DualstackCounterpartQtype("A"); got != "AAAA" {
		t.Fatalf("A counterpart = %q, want AAAA", got)
	}
	if got := DualstackCounterpartQtype("AAAA"); got != "A" {
		t.Fatalf("AAAA counterpart = %q, want A", got)
	}
	if got := DualstackCounterpartQtype("MX"); got != "" {
		t.Fatalf("MX counterpart = %q, want empty", got)
	}
}

func TestShouldSuppressMarginRule(t *testing.T) {
	cfg := DefaultDualstackConfig()
	// IPv6 (counterpart of the A query) faster by 600ms > 500ms margin → force.
	d := ShouldSuppressAnsweredFamily("A", 900, 300, cfg)
	if !d.ForceSOA {
		t.Fatalf("expected force, got %+v", d)
	}
	// Faster by exactly the margin still forces (<=).
	d = ShouldSuppressAnsweredFamily("A", 800, 300, cfg)
	if !d.ForceSOA {
		t.Fatalf("expected force at exact margin, got %+v", d)
	}
	// Faster but below the margin → keep answered family.
	d = ShouldSuppressAnsweredFamily("A", 700, 300, cfg)
	if d.ForceSOA {
		t.Fatalf("did not expect force below margin, got %+v", d)
	}
	// Counterpart slower → keep.
	d = ShouldSuppressAnsweredFamily("A", 100, 500, cfg)
	if d.ForceSOA {
		t.Fatalf("did not expect force when slower, got %+v", d)
	}
	// Unknown counterpart latency → keep.
	d = ShouldSuppressAnsweredFamily("A", 100, 0, cfg)
	if d.ForceSOA {
		t.Fatalf("did not expect force with unknown latency, got %+v", d)
	}
}

func TestShouldSuppressDisabledAndAllowFlags(t *testing.T) {
	cfg := DefaultDualstackConfig()
	cfg.Enabled = false
	if d := ShouldSuppressAnsweredFamily("A", 900, 100, cfg); d.ForceSOA {
		t.Fatalf("disabled config must not force: %+v", d)
	}

	cfg = DefaultDualstackConfig()
	cfg.AllowForceIPv6 = false
	if d := ShouldSuppressAnsweredFamily("A", 900, 100, cfg); d.ForceSOA {
		t.Fatalf("AllowForceIPv6=false must not force A suppression: %+v", d)
	}
	if d := ShouldSuppressAnsweredFamily("AAAA", 900, 100, cfg); !d.ForceSOA {
		t.Fatalf("AAAA suppression still allowed: %+v", d)
	}

	cfg = DefaultDualstackConfig()
	cfg.AllowForceIPv4 = false
	if d := ShouldSuppressAnsweredFamily("AAAA", 900, 100, cfg); d.ForceSOA {
		t.Fatalf("AllowForceIPv4=false must not force AAAA suppression: %+v", d)
	}
}

func TestShouldSuppressPreferenceOverrides(t *testing.T) {
	cfg := DefaultDualstackConfig()
	cfg.Preference = DualstackPreferIPv6
	if d := ShouldSuppressAnsweredFamily("A", 50, 900, cfg); !d.ForceSOA {
		t.Fatalf("prefer_ipv6 must force even when slower: %+v", d)
	}
	if d := ShouldSuppressAnsweredFamily("AAAA", 50, 900, cfg); d.ForceSOA {
		t.Fatalf("prefer_ipv6 must not suppress AAAA: %+v", d)
	}

	cfg.Preference = DualstackPreferIPv4
	if d := ShouldSuppressAnsweredFamily("AAAA", 50, 900, cfg); !d.ForceSOA {
		t.Fatalf("prefer_ipv4 must force even when slower: %+v", d)
	}
	if d := ShouldSuppressAnsweredFamily("A", 50, 900, cfg); d.ForceSOA {
		t.Fatalf("prefer_ipv4 must not suppress A: %+v", d)
	}
}

func TestDualstackConfigValidate(t *testing.T) {
	if err := DefaultDualstackConfig().Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
	bad := DefaultDualstackConfig()
	bad.ThresholdMs = -1
	if err := bad.Validate(); err == nil {
		t.Fatal("negative threshold must fail validation")
	}
	bad = DefaultDualstackConfig()
	bad.ThresholdMs = 60001
	if err := bad.Validate(); err == nil {
		t.Fatal("threshold above 60000 must fail validation")
	}
	bad = DefaultDualstackConfig()
	bad.Preference = "sometimes"
	if err := bad.Validate(); err == nil {
		t.Fatal("unknown preference must fail validation")
	}
}

func TestDualstackSelectorReadinessGating(t *testing.T) {
	cfg := DefaultDualstackConfig()

	sel, err := NewDualstackSelector(cfg, staticProbe(false))
	if err != nil {
		t.Fatalf("selector construction failed: %v", err)
	}
	if d := sel.Decide("A", 900, 100); d.ForceSOA || d.Reason != "ipv6 not ready" {
		t.Fatalf("expected ipv6-not-ready gate, got %+v", d)
	}

	sel, err = NewDualstackSelector(cfg, staticProbe(true))
	if err != nil {
		t.Fatalf("selector construction failed: %v", err)
	}
	if d := sel.Decide("A", 900, 100); !d.ForceSOA {
		t.Fatalf("expected force with ready ipv6, got %+v", d)
	}
	if d := sel.Decide("MX", 900, 100); d.ForceSOA || d.Reason != "qtype not dualstack-eligible" {
		t.Fatalf("MX must be ineligible, got %+v", d)
	}

	if _, err := NewDualstackSelector(DualstackConfig{Enabled: true, ThresholdMs: -5}, nil); err == nil {
		t.Fatal("invalid config must fail selector construction")
	}
}

func TestCachedIPv6Readiness(t *testing.T) {
	var calls int
	probe := probeFunc(func() bool {
		calls++
		return true
	})
	cached := NewCachedIPv6Readiness(probe, time.Hour)
	for i := 0; i < 5; i++ {
		if !cached.IPv6Ready() {
			t.Fatalf("iteration %d: expected ready", i)
		}
	}
	if calls != 1 {
		t.Fatalf("probe called %d times, want 1 (TTL cache)", calls)
	}
	if (*CachedIPv6Readiness)(nil).IPv6Ready() {
		t.Fatal("nil receiver must report not ready")
	}
	if NewCachedIPv6Readiness(probe, 0).ttl != time.Minute {
		t.Fatal("non-positive ttl must fall back to one minute")
	}
}

type probeFunc func() bool

func (f probeFunc) IPv6Ready() bool { return f() }

func TestDualstackReasonsAreBounded(t *testing.T) {
	cfg := DefaultDualstackConfig()
	for _, d := range []DualstackDecision{
		ShouldSuppressAnsweredFamily("A", 900, 100, cfg),
		ShouldSuppressAnsweredFamily("A", 100, 900, cfg),
		ShouldSuppressAnsweredFamily("A", 0, 0, cfg),
	} {
		if len(d.Reason) > 200 {
			t.Fatalf("reason too long: %q", d.Reason)
		}
		if strings.ContainsAny(d.Reason, "\n\r") {
			t.Fatalf("reason must be single-line: %q", d.Reason)
		}
	}
}
