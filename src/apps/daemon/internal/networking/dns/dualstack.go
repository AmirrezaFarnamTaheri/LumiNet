// Copyright 2024 LumiNet. Use of this source code is governed by the MIT license.

//
// Clean-room Go implementation of the observable dualstack-selection
// semantics: when a resolver answers an A (or AAAA) query and the opposite
// address family is measurably faster by a configured margin, the answered
// family is suppressed (an empty/SOA answer is forced) so clients converge on
// the faster family. IPv6 egress readiness is modeled as an injectable probe
// instead of smartdns's direct ICMP/TCP-SYN pings, keeping this owner pure and
// testable. Per policy the source corpus is treated as MIT-licensed.

package dns

import (
	"fmt"
	"sync"
	"time"
)

// DNS question types handled by the dualstack selector.
const (
	DualstackQtypeA    = "A"
	DualstackQtypeAAAA = "AAAA"
)

// DualstackPreference is the configured family preference.
type DualstackPreference string

const (
	// DualstackAuto applies the pure margin rule.
	DualstackAuto DualstackPreference = "auto"
	// DualstackPreferIPv4 always suppresses AAAA answers (when allowed).
	DualstackPreferIPv4 DualstackPreference = "prefer_ipv4"
	// DualstackPreferIPv6 always suppresses A answers (when allowed).
	DualstackPreferIPv6 DualstackPreference = "prefer_ipv6"
)

// DualstackConfig configures the dualstack selector.
type DualstackConfig struct {
	// Enabled gates the whole selection; when false no answer is suppressed.
	Enabled bool
	// ThresholdMs is the minimum improvement in milliseconds the opposite
	// family must show before the answered family is suppressed. smartdns
	// expresses this as dns_dualstack_ip_selection_threshold in 10ms units;
	// LumiNet stores the already-converted millisecond value (default 500).
	ThresholdMs int
	// AllowForceIPv4 permits suppressing AAAA answers in favour of faster IPv4.
	AllowForceIPv4 bool
	// AllowForceIPv6 permits suppressing A answers in favour of faster IPv6.
	AllowForceIPv6 bool
	// Preference overrides the margin rule when not DualstackAuto.
	Preference DualstackPreference
}

// DefaultDualstackConfig mirrors smartdns defaults (threshold 50 ×10ms = 500ms,
// both families forceable, auto preference).
func DefaultDualstackConfig() DualstackConfig {
	return DualstackConfig{
		Enabled:        true,
		ThresholdMs:    500,
		AllowForceIPv4: true,
		AllowForceIPv6: true,
		Preference:     DualstackAuto,
	}
}

// Validate rejects out-of-bounds thresholds and unknown preferences.
func (c DualstackConfig) Validate() error {
	if c.ThresholdMs < 0 || c.ThresholdMs > 60000 {
		return fmt.Errorf("dualstack: threshold %dms outside [0, 60000]", c.ThresholdMs)
	}
	switch c.Preference {
	case DualstackAuto, DualstackPreferIPv4, DualstackPreferIPv6:
	default:
		return fmt.Errorf("dualstack: unknown preference %q", c.Preference)
	}
	return nil
}

// DualstackCounterpartQtype returns the opposite record family, or "" for
// question types the selector does not handle.
func DualstackCounterpartQtype(qtype string) string {
	switch qtype {
	case DualstackQtypeA:
		return DualstackQtypeAAAA
	case DualstackQtypeAAAA:
		return DualstackQtypeA
	default:
		return ""
	}
}

// DualstackDecision reports whether the answered family must be suppressed.
type DualstackDecision struct {
	// ForceSOA is true when the answered family must be suppressed and an
	// empty (SOA) answer returned so the client re-queries the faster family.
	ForceSOA bool
	// Reason explains the decision for logs and diagnostics.
	Reason string
}

// ShouldSuppressAnsweredFamily applies the margin rule. requestedPingMs is the
// RTT of the family actually queried; counterpartPingMs is the RTT observed by
// the opposite-family probe (non-positive means unknown, which never forces).
// This function is pure; readiness gating lives on DualstackSelector.
func ShouldSuppressAnsweredFamily(qtype string, requestedPingMs, counterpartPingMs float64, cfg DualstackConfig) DualstackDecision {
	if !cfg.Enabled {
		return DualstackDecision{Reason: "dualstack disabled"}
	}
	switch cfg.Preference {
	case DualstackPreferIPv4:
		if qtype == DualstackQtypeAAAA && cfg.AllowForceIPv4 {
			return DualstackDecision{ForceSOA: true, Reason: "preference ipv4"}
		}
		return DualstackDecision{Reason: "preference keeps answered family"}
	case DualstackPreferIPv6:
		if qtype == DualstackQtypeA && cfg.AllowForceIPv6 {
			return DualstackDecision{ForceSOA: true, Reason: "preference ipv6"}
		}
		return DualstackDecision{Reason: "preference keeps answered family"}
	}
	if requestedPingMs <= 0 || counterpartPingMs <= 0 {
		return DualstackDecision{Reason: "counterpart latency unknown"}
	}
	margin := float64(cfg.ThresholdMs)
	if counterpartPingMs+margin <= requestedPingMs {
		switch qtype {
		case DualstackQtypeA:
			if cfg.AllowForceIPv6 {
				return DualstackDecision{
					ForceSOA: true,
					Reason:   fmt.Sprintf("ipv6 faster by %.0fms (margin %.0fms)", requestedPingMs-counterpartPingMs, margin),
				}
			}
		case DualstackQtypeAAAA:
			if cfg.AllowForceIPv4 {
				return DualstackDecision{
					ForceSOA: true,
					Reason:   fmt.Sprintf("ipv4 faster by %.0fms (margin %.0fms)", requestedPingMs-counterpartPingMs, margin),
				}
			}
		}
		return DualstackDecision{Reason: "faster family not allowed by policy"}
	}
	return DualstackDecision{Reason: "counterpart not faster by margin"}
}

// IPv6ReadinessProbe reports whether the host currently has usable IPv6
// egress. Implementations own their own reachability mechanics.
type IPv6ReadinessProbe interface {
	IPv6Ready() bool
}

// CachedIPv6Readiness wraps a probe with a TTL-bounded cache so hot decision
// paths never hammer the underlying reachability check. A nil probe reports
// "not ready" (dualstack selection disabled), matching smartdns behavior when
// no ping mechanism is available.
type CachedIPv6Readiness struct {
	probe     IPv6ReadinessProbe
	ttl       time.Duration
	mu        sync.Mutex
	last      bool
	checkedAt time.Time
}

// NewCachedIPv6Readiness builds a cached readiness view. A non-positive ttl
// falls back to one minute.
func NewCachedIPv6Readiness(probe IPv6ReadinessProbe, ttl time.Duration) *CachedIPv6Readiness {
	if ttl <= 0 {
		ttl = time.Minute
	}
	return &CachedIPv6Readiness{probe: probe, ttl: ttl}
}

// IPv6Ready reports the cached readiness, refreshing through the probe when
// the TTL has expired.
func (c *CachedIPv6Readiness) IPv6Ready() bool {
	if c == nil || c.probe == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.checkedAt.IsZero() && time.Since(c.checkedAt) < c.ttl {
		return c.last
	}
	c.last = c.probe.IPv6Ready()
	c.checkedAt = time.Now()
	return c.last
}

// DualstackSelector binds a config and an IPv6 readiness probe into the
// decision surface the resolver layer calls per query.
type DualstackSelector struct {
	cfg       DualstackConfig
	readiness IPv6ReadinessProbe
}

// NewDualstackSelector validates the config and returns a selector. A nil
// probe disables selection entirely (IPv6 never ready).
func NewDualstackSelector(cfg DualstackConfig, readiness IPv6ReadinessProbe) (*DualstackSelector, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &DualstackSelector{cfg: cfg, readiness: readiness}, nil
}

// Config returns the selector's effective configuration.
func (s *DualstackSelector) Config() DualstackConfig { return s.cfg }

// Decide applies readiness gating plus the margin/preference rule for the
// answered family. Requests for types other than A/AAAA are never suppressed.
func (s *DualstackSelector) Decide(qtype string, requestedPingMs, counterpartPingMs float64) DualstackDecision {
	if DualstackCounterpartQtype(qtype) == "" {
		return DualstackDecision{Reason: "qtype not dualstack-eligible"}
	}
	// smartdns: is_ipv6_ready == 0 disables dualstack selection entirely.
	if s.readiness == nil || !s.readiness.IPv6Ready() {
		return DualstackDecision{Reason: "ipv6 not ready"}
	}
	return ShouldSuppressAnsweredFamily(qtype, requestedPingMs, counterpartPingMs, s.cfg)
}