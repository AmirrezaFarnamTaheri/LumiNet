package diagnostics

import (
	"fmt"
	"math"
	"sort"
)

type WorkerEndpoint struct {
	Domain        string
	CleanIP       string
	Port          uint16
	LatencyMs     uint64
	PacketLossPct float32
}

func (w *WorkerEndpoint) Score() float64 {
	return float64(w.LatencyMs) + float64(w.PacketLossPct)*150.0
}

type EdgeWorkerSelector struct {
	endpoints []WorkerEndpoint
}

func NewEdgeWorkerSelector() *EdgeWorkerSelector {
	return &EdgeWorkerSelector{
		endpoints: make([]WorkerEndpoint, 0),
	}
}

func (s *EdgeWorkerSelector) AddOrUpdate(domain, cleanIP string, port uint16, latencyMs uint64, loss float32) {
	for i := range s.endpoints {
		if s.endpoints[i].Domain == domain && s.endpoints[i].CleanIP == cleanIP {
			s.endpoints[i].Port = port
			s.endpoints[i].LatencyMs = latencyMs
			s.endpoints[i].PacketLossPct = loss
			return
		}
	}
	s.endpoints = append(s.endpoints, WorkerEndpoint{
		Domain:        domain,
		CleanIP:       cleanIP,
		Port:          port,
		LatencyMs:     latencyMs,
		PacketLossPct: loss,
	})
}

func (s *EdgeWorkerSelector) SelectBest() *WorkerEndpoint {
	if len(s.endpoints) == 0 {
		return nil
	}
	bestIdx := 0
	bestScore := math.MaxFloat64
	for i := range s.endpoints {
		sc := s.endpoints[i].Score()
		if sc < bestScore {
			bestScore = sc
			bestIdx = i
		}
	}
	cp := s.endpoints[bestIdx]
	return &cp
}

func (s *EdgeWorkerSelector) FilterCandidates(maxLatency uint64, maxLoss float32) []WorkerEndpoint {
	var res []WorkerEndpoint
	for _, ep := range s.endpoints {
		if ep.LatencyMs <= maxLatency && ep.PacketLossPct <= maxLoss {
			res = append(res, ep)
		}
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].Score() < res[j].Score()
	})
	return res
}

func (s *EdgeWorkerSelector) SynthesizeVlessURI(ep *WorkerEndpoint, uuid, sni string) string {
	return fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=tls&sni=%s&type=ws&host=%s&path=%%2F#LumiNet-Worker",
		uuid, ep.CleanIP, ep.Port, sni, ep.Domain)
}
