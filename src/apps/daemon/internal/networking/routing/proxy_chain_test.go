package routing

import (
	"errors"
	"testing"
)

func TestResolveProxyChain_Disabled(t *testing.T) {
	base := ProxyProfileRef{SubscriptionID: "sub1", Fingerprint: "fp_base", Name: "Base Node"}
	settings := ProxyChainSettings{Enabled: false}

	route, err := ResolveProxyChain(base, settings, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(route.Hops) != 1 || route.Hops[0].Fingerprint != "fp_base" {
		t.Fatalf("expected single base hop, got %+v", route.Hops)
	}
	if route.IsChained {
		t.Fatalf("expected IsChained false")
	}
}

func TestResolveProxyChain_3Hops(t *testing.T) {
	before := ProxyProfileRef{SubscriptionID: "sub1", Fingerprint: "fp_before", Name: "Before Node"}
	base := ProxyProfileRef{SubscriptionID: "sub1", Fingerprint: "fp_base", Name: "Base Node"}
	after := ProxyProfileRef{SubscriptionID: "sub2", Fingerprint: "fp_after", Name: "After Node"}

	settings := ProxyChainSettings{
		Enabled: true,
		Before:  ProxyChainHop{Slot: "before", Mode: HopModeFixed, FixedRef: &before},
		After:   ProxyChainHop{Slot: "after", Mode: HopModeFixed, FixedRef: &after},
	}

	route, err := ResolveProxyChain(base, settings, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(route.Hops) != 3 {
		t.Fatalf("expected 3 hops, got %d", len(route.Hops))
	}
	if route.Hops[0].Fingerprint != "fp_before" || route.Hops[1].Fingerprint != "fp_base" || route.Hops[2].Fingerprint != "fp_after" {
		t.Fatalf("unexpected hop sequence: %+v", route.Hops)
	}
	if !route.IsChained {
		t.Fatalf("expected IsChained true")
	}
}

func TestResolveProxyChain_LoopDetected(t *testing.T) {
	base := ProxyProfileRef{SubscriptionID: "sub1", Fingerprint: "fp_dup", Name: "Dup Node"}
	settings := ProxyChainSettings{
		Enabled: true,
		Before:  ProxyChainHop{Slot: "before", Mode: HopModeFixed, FixedRef: &base},
	}

	_, err := ResolveProxyChain(base, settings, nil)
	if err == nil || !errors.Is(err, ErrLoopDetected) {
		t.Fatalf("expected ErrLoopDetected, got %v", err)
	}
}

func TestResolveProxyChain_AutomaticSelection(t *testing.T) {
	base := ProxyProfileRef{SubscriptionID: "sub1", Fingerprint: "fp_base", Name: "Base Node"}
	cand1 := ProxyProfileRef{SubscriptionID: "sub1", Fingerprint: "fp_base", Name: "Duplicate Base"}
	cand2 := ProxyProfileRef{SubscriptionID: "sub1", Fingerprint: "fp_cand2", Name: "Alternative Node"}

	settings := ProxyChainSettings{
		Enabled: true,
		Before:  ProxyChainHop{Slot: "before", Mode: HopModeAutomatic},
	}

	route, err := ResolveProxyChain(base, settings, []ProxyProfileRef{cand1, cand2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(route.Hops) != 2 || route.Hops[0].Fingerprint != "fp_cand2" {
		t.Fatalf("expected cand2 selected for before hop, got %+v", route.Hops)
	}
}
