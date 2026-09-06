package proxyconfig

import (
	"fmt"
	"strings"
	"sync"

	"github.com/maybeknott/luminet/internal/networking/routing"
)

type AutonomousIngestPipeline struct {
	mu            sync.RWMutex
	Deduplicator  *NodeIngestDeduplicator
	GeoIP         *routing.EnhancedGeoIpLookup
	RuleCompiler  *routing.CompositeRuleCompiler
	PolicyRouter  *routing.PolicyRulesetRouter
	TotalIngested int
}

func NewAutonomousIngestPipeline(defaultPolicy routing.PolicyVerdict) *AutonomousIngestPipeline {
	return &AutonomousIngestPipeline{
		Deduplicator:  NewNodeIngestDeduplicator(),
		GeoIP:         routing.NewEnhancedGeoIpLookup(),
		RuleCompiler:  routing.NewCompositeRuleCompiler(),
		PolicyRouter:  routing.NewPolicyRulesetRouter(defaultPolicy),
		TotalIngested: 0,
	}
}

func (p *AutonomousIngestPipeline) IngestSubscriptionManifest(sourceName, b64Manifest string) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	extractor := &SubscriptionNodeExtractor{}
	nodes := extractor.DecodeSubscription(b64Manifest)
	added := 0

	for _, node := range nodes {
		scraped := ScrapedNode{
			Host:     node.Address,
			Port:     node.Port,
			Protocol: strings.ToLower(fmt.Sprintf("%v", node.NodeType)),
			Source:   sourceName,
			PingMs:   100,
			IsAlive:  true,
		}
		if p.Deduplicator.IngestNode(scraped) {
			added++
		}
	}

	p.TotalIngested += added
	return added
}

func (p *AutonomousIngestPipeline) EvaluateEgress(targetDomain string, destIP *[4]byte) routing.PolicyVerdict {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 1. Composite rule check (highest specificity)
	if act, ok := p.RuleCompiler.EvaluateDomain(targetDomain); ok {
		switch act {
		case routing.RuleActionDirect:
			return routing.PolicyVerdictDirect
		case routing.RuleActionProxy:
			return routing.PolicyVerdictProxy
		case routing.RuleActionReject:
			return routing.PolicyVerdictReject
		}
	}

	// 2. IP GeoIP rule check if IP provided
	if destIP != nil {
		if cc, ok := p.GeoIP.Lookup(*destIP); ok {
			if cc == "CN" {
				return routing.PolicyVerdictDirect
			}
		}
	}

	// 3. Fallback to policy router
	return p.PolicyRouter.ResolveDomain(targetDomain)
}
