package routing

import (
	"errors"
	"fmt"
)

var (
	ErrLoopDetected         = errors.New("loop detected in proxy chain")
	ErrNoCandidatesAvailable = errors.New("no distinct candidates available for slot")
)

type HopMode string

const (
	HopModeOff       HopMode = "off"
	HopModeAutomatic HopMode = "automatic"
	HopModeFixed     HopMode = "fixed"
)

// ProxyProfileRef points to an available proxy profile by subscription and fingerprint.
type ProxyProfileRef struct {
	SubscriptionID string `json:"subscriptionId"`
	Fingerprint    string `json:"fingerprint"`
	Name           string `json:"name"`
}

// ProxyChainHop defines one chained slot policy (Before or After).
type ProxyChainHop struct {
	Slot     string           `json:"slot"`
	Mode     HopMode          `json:"mode"`
	FixedRef *ProxyProfileRef `json:"fixedRef,omitempty"`
}

// ProxyChainSettings holds 3-hop proxy chaining configuration.
type ProxyChainSettings struct {
	Enabled bool          `json:"enabled"`
	Before  ProxyChainHop `json:"before"`
	After   ProxyChainHop `json:"after"`
}

// ProxyChainResolvedRoute holds the concrete sequence of hops for tunnel routing.
type ProxyChainResolvedRoute struct {
	Hops      []ProxyProfileRef `json:"hops"`
	IsChained bool              `json:"isChained"`
}

// ResolveProxyChain builds an ordered proxy chain, preventing loops and duplicate nodes.
func ResolveProxyChain(
	base ProxyProfileRef,
	settings ProxyChainSettings,
	available []ProxyProfileRef,
) (ProxyChainResolvedRoute, error) {
	if !settings.Enabled {
		return ProxyChainResolvedRoute{
			Hops:      []ProxyProfileRef{base},
			IsChained: false,
		}, nil
	}

	var hops []ProxyProfileRef
	var beforeResolved *ProxyProfileRef

	// 1. Resolve Before Hop
	switch settings.Before.Mode {
	case HopModeOff, "":
		// disabled
	case HopModeFixed:
		if settings.Before.FixedRef == nil {
			return ProxyChainResolvedRoute{}, fmt.Errorf("fixed before hop profile ref is nil")
		}
		if settings.Before.FixedRef.Fingerprint == base.Fingerprint {
			return ProxyChainResolvedRoute{}, fmt.Errorf("%w: before hop duplicates base fingerprint %s", ErrLoopDetected, base.Fingerprint)
		}
		beforeResolved = settings.Before.FixedRef
		hops = append(hops, *beforeResolved)
	case HopModeAutomatic:
		for _, cand := range available {
			if cand.Fingerprint != base.Fingerprint {
				c := cand
				beforeResolved = &c
				hops = append(hops, c)
				break
			}
		}
		if beforeResolved == nil {
			return ProxyChainResolvedRoute{}, fmt.Errorf("%w: before", ErrNoCandidatesAvailable)
		}
	}

	// 2. Add Base Hop
	hops = append(hops, base)

	// 3. Resolve After Hop
	switch settings.After.Mode {
	case HopModeOff, "":
		// disabled
	case HopModeFixed:
		if settings.After.FixedRef == nil {
			return ProxyChainResolvedRoute{}, fmt.Errorf("fixed after hop profile ref is nil")
		}
		if settings.After.FixedRef.Fingerprint == base.Fingerprint {
			return ProxyChainResolvedRoute{}, fmt.Errorf("%w: after hop duplicates base fingerprint %s", ErrLoopDetected, base.Fingerprint)
		}
		if beforeResolved != nil && settings.After.FixedRef.Fingerprint == beforeResolved.Fingerprint {
			return ProxyChainResolvedRoute{}, fmt.Errorf("%w: after hop duplicates before fingerprint %s", ErrLoopDetected, beforeResolved.Fingerprint)
		}
		hops = append(hops, *settings.After.FixedRef)
	case HopModeAutomatic:
		var afterResolved *ProxyProfileRef
		for _, cand := range available {
			if cand.Fingerprint != base.Fingerprint && (beforeResolved == nil || cand.Fingerprint != beforeResolved.Fingerprint) {
				c := cand
				afterResolved = &c
				hops = append(hops, c)
				break
			}
		}
		if afterResolved == nil {
			return ProxyChainResolvedRoute{}, fmt.Errorf("%w: after", ErrNoCandidatesAvailable)
		}
	}

	return ProxyChainResolvedRoute{
		Hops:      hops,
		IsChained: len(hops) > 1,
	}, nil
}
