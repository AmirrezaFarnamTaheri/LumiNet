package routing

import (
	"net"
	"sync"

	"github.com/maybeknott/luminet/internal/networking/diagnostics"
	"github.com/maybeknott/luminet/internal/platform/security"
)

type FilterVerdictType int

const (
	VerdictDirectPassThrough FilterVerdictType = iota
	VerdictBlockedDns
	VerdictProxyRequired
)

type FilterVerdict struct {
	Type      FilterVerdictType
	Category  security.BlockCategory
	RuleHit   string
	EgressTag string
}

type IntelligentTrafficFilter struct {
	DnsBlocklist   *security.DnsBlocklistEngine
	CanonicalRules *CanonicalBlacklistEngine
	GeoRouter      *GeospatialPolygonRouter
	FlowAnalyzer   *diagnostics.FlowAnalyzerEngine
	totalQueries   uint64
	mu             sync.Mutex
}

func NewIntelligentTrafficFilter(defaultEgress string) *IntelligentTrafficFilter {
	return &IntelligentTrafficFilter{
		DnsBlocklist:   security.NewDnsBlocklistEngine(),
		CanonicalRules: NewCanonicalBlacklistEngine(),
		GeoRouter:      NewGeospatialPolygonRouter(defaultEgress),
		FlowAnalyzer:   diagnostics.NewFlowAnalyzerEngine(),
	}
}

func (f *IntelligentTrafficFilter) EvaluateTraffic(
	src, dst *net.TCPAddr,
	domain string,
	userLoc *GeoPoint,
	initialPayload []byte,
) FilterVerdict {
	f.mu.Lock()
	f.totalQueries++
	f.mu.Unlock()

	// 1. Register flow
	_ = f.FlowAnalyzer.RegisterFlow(src, dst, initialPayload)

	// 2. DNS Blocklist
	if domain != "" {
		if cat, blocked := f.DnsBlocklist.IsDomainBlocked(domain); blocked {
			return FilterVerdict{
				Type:     VerdictBlockedDns,
				Category: cat,
			}
		}
	}

	// 3. Resolve spatial egress
	spatialEgress := "default-direct"
	if userLoc != nil {
		spatialEgress, _ = f.GeoRouter.ResolveEgress(*userLoc)
	}

	// 4. Blacklist matching
	if domain != "" {
		match, rule := f.CanonicalRules.EvaluateTarget(domain)
		if match == MatchBlocked {
			return FilterVerdict{
				Type:      VerdictProxyRequired,
				RuleHit:   rule,
				EgressTag: "tunnel-proxy",
			}
		}
	}

	return FilterVerdict{
		Type:      VerdictDirectPassThrough,
		EgressTag: spatialEgress,
	}
}
