package diagnostics

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
)

const maxDNSPolicyTransports = 32

type DNSPolicyTransport struct {
	ID                   string `json:"id"`
	Kind                 string `json:"kind"`
	Server               string `json:"server,omitempty"`
	FallbackTo           string `json:"fallback_to,omitempty"`
	TruncationFallbackTo string `json:"truncation_fallback_to,omitempty"`
	RouteThrough         string `json:"route_through,omitempty"`
	EDNSClientSubnet     string `json:"edns_client_subnet,omitempty"`
}

type DNSResolutionPolicyRequest struct {
	Transports             []DNSPolicyTransport `json:"transports"`
	PrimaryTransport       string               `json:"primary_transport"`
	Strategy               string               `json:"strategy,omitempty"`
	CacheScope             string               `json:"cache_scope,omitempty"`
	RewriteTTLSeconds      int                  `json:"rewrite_ttl_seconds,omitempty"`
	ResponseRejectionCache bool                 `json:"response_rejection_cache,omitempty"`
	RequireSecureTransport bool                 `json:"require_secure_transport,omitempty"`
}

type DNSPolicyTransportPlan struct {
	ID                   string `json:"id"`
	Kind                 string `json:"kind"`
	Secure               bool   `json:"secure"`
	FallbackTo           string `json:"fallback_to,omitempty"`
	TruncationFallbackTo string `json:"truncation_fallback_to,omitempty"`
	ECSPrivacyImpact     bool   `json:"ecs_privacy_impact"`
}

type DNSResolutionPolicyPlan struct {
	Transports        []DNSPolicyTransportPlan `json:"transports"`
	PrimaryTransport  string                   `json:"primary_transport"`
	LookupFamilies    []string                 `json:"lookup_families"`
	CacheScope        string                   `json:"cache_scope"`
	RewriteTTLSeconds int                      `json:"rewrite_ttl_seconds,omitempty"`
	Warnings          []string                 `json:"warnings"`
	Invariants        []string                 `json:"invariants"`
	ReadOnly          bool                     `json:"read_only"`
}

func dnsTransportSecure(kind string) bool {
	switch kind {
	case "tls", "https", "quic", "http3":
		return true
	}
	return false
}
func validDNSKind(kind string) bool {
	switch kind {
	case "udp", "tcp", "tls", "https", "quic", "http3", "local", "rcode", "hosts":
		return true
	}
	return false
}

func BuildDNSResolutionPolicyPlan(req DNSResolutionPolicyRequest) (DNSResolutionPolicyPlan, error) {
	if len(req.Transports) == 0 || len(req.Transports) > maxDNSPolicyTransports {
		return DNSResolutionPolicyPlan{}, fmt.Errorf("DNS transport count must be between 1 and %d", maxDNSPolicyTransports)
	}
	byID := make(map[string]DNSPolicyTransport, len(req.Transports))
	for _, t := range req.Transports {
		id := strings.TrimSpace(t.ID)
		kind := strings.ToLower(strings.TrimSpace(t.Kind))
		if id == "" || len(id) > 128 || !validDNSKind(kind) {
			return DNSResolutionPolicyPlan{}, fmt.Errorf("invalid DNS transport %q/%q", id, kind)
		}
		if _, exists := byID[id]; exists {
			return DNSResolutionPolicyPlan{}, fmt.Errorf("duplicate DNS transport %q", id)
		}
		t.ID, t.Kind = id, kind
		byID[id] = t
	}
	primary := strings.TrimSpace(req.PrimaryTransport)
	if _, ok := byID[primary]; !ok {
		return DNSResolutionPolicyPlan{}, fmt.Errorf("primary DNS transport %q is unknown", primary)
	}
	cache := strings.ToLower(strings.TrimSpace(req.CacheScope))
	if cache == "" {
		cache = "shared"
	}
	if cache != "shared" && cache != "per-transport" && cache != "disabled" {
		return DNSResolutionPolicyPlan{}, fmt.Errorf("cache scope must be shared, per-transport, or disabled")
	}
	if req.RewriteTTLSeconds < 0 || req.RewriteTTLSeconds > 86400 {
		return DNSResolutionPolicyPlan{}, fmt.Errorf("rewrite TTL must be between 0 and 86400 seconds")
	}
	strategy := strings.ToLower(strings.TrimSpace(req.Strategy))
	if strategy == "" {
		strategy = "as-is"
	}
	families := map[string][]string{"as-is": {"requested"}, "prefer-ipv4": {"ipv4", "ipv6"}, "prefer-ipv6": {"ipv6", "ipv4"}, "ipv4-only": {"ipv4"}, "ipv6-only": {"ipv6"}}
	lookup, ok := families[strategy]
	if !ok {
		return DNSResolutionPolicyPlan{}, fmt.Errorf("unsupported DNS strategy %q", strategy)
	}

	// Route-through is a dependency graph; reject loops before producing advice.
	visiting, done := map[string]bool{}, map[string]bool{}
	var visit func(string) error
	visit = func(id string) error {
		if done[id] {
			return nil
		}
		if visiting[id] {
			return fmt.Errorf("DNS transport route loop at %q", id)
		}
		visiting[id] = true
		dep := strings.TrimSpace(byID[id].RouteThrough)
		if dep != "" {
			if _, ok := byID[dep]; !ok {
				return fmt.Errorf("DNS transport %q routes through unknown %q", id, dep)
			}
			if err := visit(dep); err != nil {
				return err
			}
		}
		visiting[id] = false
		done[id] = true
		return nil
	}
	for id := range byID {
		if err := visit(id); err != nil {
			return DNSResolutionPolicyPlan{}, err
		}
	}

	plan := DNSResolutionPolicyPlan{PrimaryTransport: primary, LookupFamilies: lookup, CacheScope: cache, RewriteTTLSeconds: req.RewriteTTLSeconds, ReadOnly: true, Warnings: []string{}, Invariants: []string{"query correlation cleanup must delete the exact allocated wire ID", "TTL rewrite must be identical for A and AAAA materialization", "secure transports never silently downgrade to plaintext", "transport route dependencies must be acyclic"}}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		t := byID[id]
		secure := dnsTransportSecure(t.Kind)
		for _, target := range []struct{ name, value string }{{"fallback", strings.TrimSpace(t.FallbackTo)}, {"truncation fallback", strings.TrimSpace(t.TruncationFallbackTo)}} {
			if target.value == "" {
				continue
			}
			dest, ok := byID[target.value]
			if !ok {
				return DNSResolutionPolicyPlan{}, fmt.Errorf("DNS transport %q %s target %q is unknown", id, target.name, target.value)
			}
			if req.RequireSecureTransport && secure && !dnsTransportSecure(dest.Kind) {
				return DNSResolutionPolicyPlan{}, fmt.Errorf("secure DNS transport %q cannot downgrade to plaintext %q", id, target.value)
			}
		}
		if t.Kind == "udp" && strings.TrimSpace(t.TruncationFallbackTo) != "" && byID[strings.TrimSpace(t.TruncationFallbackTo)].Kind != "tcp" {
			return DNSResolutionPolicyPlan{}, fmt.Errorf("UDP truncation fallback for %q must target TCP", id)
		}
		ecs := strings.TrimSpace(t.EDNSClientSubnet) != ""
		if ecs {
			if _, _, err := net.ParseCIDR(t.EDNSClientSubnet); err != nil {
				return DNSResolutionPolicyPlan{}, fmt.Errorf("invalid ECS subnet for %q", id)
			}
			plan.Warnings = append(plan.Warnings, "EDNS client subnet leaks client network locality: "+id)
		}
		if t.Kind == "https" && t.Server != "" {
			u, err := url.Parse(t.Server)
			if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
				return DNSResolutionPolicyPlan{}, fmt.Errorf("DoH transport %q requires absolute credential-free HTTPS URL", id)
			}
		}
		plan.Transports = append(plan.Transports, DNSPolicyTransportPlan{ID: id, Kind: t.Kind, Secure: secure, FallbackTo: strings.TrimSpace(t.FallbackTo), TruncationFallbackTo: strings.TrimSpace(t.TruncationFallbackTo), ECSPrivacyImpact: ecs})
	}
	if req.ResponseRejectionCache {
		plan.Invariants = append(plan.Invariants, "response-rejection cache is separate from positive answer cache")
	}
	return plan, nil
}
