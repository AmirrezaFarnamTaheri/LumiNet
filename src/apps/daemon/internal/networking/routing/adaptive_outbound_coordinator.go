package routing

import (
	"sync"

	"github.com/maybeknott/luminet/internal/networking/diagnostics"
	"github.com/maybeknott/luminet/internal/networking/transport"
)

type AdaptiveOutboundResilienceCoordinator struct {
	mu              sync.RWMutex
	Router          *MultiOutboundRouter
	Watcher         *diagnostics.ProviderFailoverWatcher
	Masquerader     *transport.CamouflageStreamMasquerader
	CdnSorter       *transport.EdgeCdnPoolSorter
	TotalDispatched uint64
}

func NewAdaptiveOutboundResilienceCoordinator(
	defaultPolicy OutboundPolicy,
	failoverThreshold uint32,
	sharedSecret []byte,
	decoyHost string,
	maxCdnLatency uint32,
) *AdaptiveOutboundResilienceCoordinator {
	return &AdaptiveOutboundResilienceCoordinator{
		Router:          NewMultiOutboundRouter(defaultPolicy),
		Watcher:         diagnostics.NewProviderFailoverWatcher(failoverThreshold),
		Masquerader:     transport.NewCamouflageStreamMasquerader(sharedSecret, decoyHost),
		CdnSorter:       transport.NewEdgeCdnPoolSorter(maxCdnLatency),
		TotalDispatched: 0,
	}
}

func (c *AdaptiveOutboundResilienceCoordinator) RouteAndPrepareOutbound(
	targetDomain string,
	userID [16]byte,
) (OutboundPolicy, string, []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.TotalDispatched++

	// 1. Determine policy via multi outbound router
	policy := c.Router.MatchTarget(targetDomain)

	// 2. Resolve best CDN egress IP if applicable
	bestIP, _ := c.CdnSorter.BestIP()

	// 3. Generate obfuscated session preamble for camouflage transport
	preamble := c.Masquerader.GeneratePreamble(userID)

	return policy, bestIP, preamble
}

func (c *AdaptiveOutboundResilienceCoordinator) HandleInboundProbe(preamble []byte) transport.ProbeAction {
	return c.Masquerader.InspectInboundStream(preamble)
}
