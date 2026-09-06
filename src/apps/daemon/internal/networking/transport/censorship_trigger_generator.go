package transport

import (
	"fmt"
	"sync"
)

type ProbeCategory string

const (
	ProbeCategoryHostHeader   ProbeCategory = "HostHeader"
	ProbeCategoryPathKeyword  ProbeCategory = "PathKeyword"
	ProbeCategorySniPattern   ProbeCategory = "SniPattern"
	ProbeCategoryDnsQueryName ProbeCategory = "DnsQueryName"
)

type TriggerProbeSpec struct {
	Category               ProbeCategory
	PayloadString          string
	ExpectedBlockMechanism string
}

type CensorshipTriggerGenerator struct {
	mu       sync.RWMutex
	triggers []TriggerProbeSpec
}

func NewCensorshipTriggerGenerator() *CensorshipTriggerGenerator {
	gen := &CensorshipTriggerGenerator{
		triggers: make([]TriggerProbeSpec, 0),
	}
	gen.populateDefaultTriggers()
	return gen
}

func (g *CensorshipTriggerGenerator) populateDefaultTriggers() {
	g.triggers = append(g.triggers,
		TriggerProbeSpec{
			Category:               ProbeCategorySniPattern,
			PayloadString:          "zh.wikipedia.org",
			ExpectedBlockMechanism: "SNI_RST",
		},
		TriggerProbeSpec{
			Category:               ProbeCategoryHostHeader,
			PayloadString:          "Host: epochtimes.com\r\n",
			ExpectedBlockMechanism: "HTTP_RESET",
		},
		TriggerProbeSpec{
			Category:               ProbeCategoryDnsQueryName,
			PayloadString:          "www.youtube.com",
			ExpectedBlockMechanism: "DNS_POISON",
		},
		TriggerProbeSpec{
			Category:               ProbeCategoryPathKeyword,
			PayloadString:          "/search?q=falun",
			ExpectedBlockMechanism: "HTTP_KEYWORD_RST",
		},
	)
}

func (g *CensorshipTriggerGenerator) AddCustomTrigger(cat ProbeCategory, payload, mechanism string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.triggers = append(g.triggers, TriggerProbeSpec{
		Category:               cat,
		PayloadString:          payload,
		ExpectedBlockMechanism: mechanism,
	})
}

func (g *CensorshipTriggerGenerator) GenerateHTTPProbe(targetHost, path string) []byte {
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: LumiProbe/1.0\r\nConnection: close\r\n\r\n", path, targetHost)
	return []byte(req)
}

func (g *CensorshipTriggerGenerator) GetProbesByCategory(cat ProbeCategory) []TriggerProbeSpec {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var res []TriggerProbeSpec
	for _, t := range g.triggers {
		if t.Category == cat {
			res = append(res, t)
		}
	}
	return res
}

func (g *CensorshipTriggerGenerator) TotalProbes() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.triggers)
}
