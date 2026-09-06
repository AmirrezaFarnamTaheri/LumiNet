package proxyconfig

import (
	"fmt"

	"github.com/maybeknott/luminet/internal/networking/diagnostics"
	"github.com/maybeknott/luminet/internal/networking/routing"
)

type OrchestratorSummary struct {
	TotalCrawled         int    `json:"total_crawled"`
	TotalActivePool      int    `json:"total_active_pool"`
	UsableTierACount     int    `json:"usable_tier_a_count"`
	CurrentPacRulesCount int    `json:"current_pac_rules_count"`
	PacChecksum          string `json:"pac_checksum"`
}

type PacSubscriptionOrchestrator struct {
	crawler          *SubscriptionCrawlerPipeline
	pool             *NodePoolAggregator
	classifier       *diagnostics.SubscriptionHealthClassifier
	pacGen           *routing.PacRuleGenerator
	pacSync          *routing.PacDiffSynchronizer
	defaultProxyPort uint16
}

func NewPacSubscriptionOrchestrator(initialDomains []string, defaultProxyPort uint16) *PacSubscriptionOrchestrator {
	pacGen := routing.NewPacRuleGenerator(routing.PacRuleActionDirect, "")
	for _, d := range initialDomains {
		pacGen.AddRule(d, routing.PacRuleActionProxy, fmt.Sprintf("127.0.0.1:%d", defaultProxyPort))
	}

	return &PacSubscriptionOrchestrator{
		crawler:          NewSubscriptionCrawlerPipeline(),
		pool:             NewNodePoolAggregator(),
		classifier:       diagnostics.NewSubscriptionHealthClassifier(10),
		pacGen:           pacGen,
		pacSync:          routing.NewPacDiffSynchronizer(initialDomains),
		defaultProxyPort: defaultProxyPort,
	}
}

func (p *PacSubscriptionOrchestrator) RegisterSubscriptionSource(url string, intervalSecs int64) {
	p.crawler.AddSource(url, intervalSecs)
}

func (p *PacSubscriptionOrchestrator) ExecuteCrawlAndIngest(sourceURL, rawContent string, now int64) int {
	count := p.crawler.IngestCrawlContent(sourceURL, rawContent)
	proxies := p.crawler.GetHarvestedProxies()
	p.pool.IngestRawEntries(proxies, now)
	return count
}

func (p *PacSubscriptionOrchestrator) RecordNodeProbe(nodeID string, latencyMs uint32, success bool) {
	p.classifier.RecordSample(nodeID, latencyMs, success)
	p.pool.UpdateHealth(nodeID, latencyMs, success)
}

func (p *PacSubscriptionOrchestrator) UpdatePacWithUpstream(upstreamDomains []string) (routing.PacSyncDelta, error) {
	delta := p.pacSync.ComputeDelta(upstreamDomains)
	if _, err := p.pacSync.ApplyDelta(delta); err != nil {
		return delta, err
	}

	p.pacGen = routing.NewPacRuleGenerator(routing.PacRuleActionDirect, "")
	for _, d := range upstreamDomains {
		p.pacGen.AddRule(d, routing.PacRuleActionProxy, fmt.Sprintf("127.0.0.1:%d", p.defaultProxyPort))
	}

	return delta, nil
}

func (p *PacSubscriptionOrchestrator) ExportActivePacScript() string {
	return p.pacGen.GeneratePacScript()
}

func (p *PacSubscriptionOrchestrator) GetSummary() OrchestratorSummary {
	tierA := p.classifier.FilterUsableNodes(diagnostics.TierAExcellent)
	return OrchestratorSummary{
		TotalCrawled:         p.crawler.TotalHarvestedCount(),
		TotalActivePool:      len(p.pool.RankNodes(0.0)),
		UsableTierACount:     len(tierA),
		CurrentPacRulesCount: p.pacSync.TotalRules(),
		PacChecksum:          p.pacSync.CurrentChecksum(),
	}
}
