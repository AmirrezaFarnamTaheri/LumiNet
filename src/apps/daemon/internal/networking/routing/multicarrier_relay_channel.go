package routing

import (
	"sort"
)

type CarrierType string

const (
	CarrierTelecom      CarrierType = "telecom"
	CarrierUnicom       CarrierType = "unicom"
	CarrierMobile       CarrierType = "mobile"
	CarrierSatellite    CarrierType = "satellite"
	CarrierOverlayRelay CarrierType = "overlay"
)

type CarrierRoute struct {
	Carrier              CarrierType
	Endpoint             string
	LatencyMs            uint32
	PacketLoss           float32
	Weight               uint32
	IsActive             bool
	ConsecutiveFailures  uint32
}

type MulticarrierRelayChannel struct {
	routes []CarrierRoute
}

func NewMulticarrierRelayChannel() *MulticarrierRelayChannel {
	return &MulticarrierRelayChannel{
		routes: make([]CarrierRoute, 0),
	}
}

func (m *MulticarrierRelayChannel) AddRoute(route CarrierRoute) {
	m.routes = append(m.routes, route)
}

func (m *MulticarrierRelayChannel) SelectBestCarrier() *CarrierRoute {
	var active []*CarrierRoute
	for i := range m.routes {
		if m.routes[i].IsActive {
			active = append(active, &m.routes[i])
		}
	}

	if len(active) == 0 {
		return nil
	}

	sort.Slice(active, func(i, j int) bool {
		return m.score(active[i]) > m.score(active[j])
	})

	return active[0]
}

func (m *MulticarrierRelayChannel) RecordFeedback(carrier CarrierType, rttMs uint32, success bool) {
	for i := range m.routes {
		r := &m.routes[i]
		if r.Carrier == carrier {
			if success {
				r.ConsecutiveFailures = 0
				r.LatencyMs = (r.LatencyMs*3 + rttMs) / 4
				r.PacketLoss = r.PacketLoss * 0.8
				r.IsActive = true
			} else {
				r.ConsecutiveFailures++
				r.PacketLoss = (r.PacketLoss * 0.8) + 0.2
				if r.ConsecutiveFailures >= 3 {
					r.IsActive = false
				}
			}
		}
	}
}

func (m *MulticarrierRelayChannel) FailoverSequence() []CarrierRoute {
	copied := make([]CarrierRoute, len(m.routes))
	copy(copied, m.routes)
	sort.Slice(copied, func(i, j int) bool {
		return m.score(&copied[i]) > m.score(&copied[j])
	})
	return copied
}

func (m *MulticarrierRelayChannel) score(r *CarrierRoute) float64 {
	lat := float64(r.LatencyMs)
	if lat < 1 {
		lat = 1
	}
	loss := float64(r.PacketLoss)
	fails := float64(r.ConsecutiveFailures)
	baseWeight := float64(r.Weight)

	return baseWeight / (lat * (1.0 + loss*5.0) * (1.0 + fails*2.0))
}
