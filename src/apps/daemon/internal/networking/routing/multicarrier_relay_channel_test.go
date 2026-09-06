package routing

import (
	"testing"
)

func TestMulticarrierRelayChannel(t *testing.T) {
	ch := NewMulticarrierRelayChannel()
	ch.AddRoute(CarrierRoute{
		Carrier:    CarrierTelecom,
		Endpoint:   "1.1.1.1:443",
		LatencyMs:  120,
		PacketLoss: 0.02,
		Weight:     100,
		IsActive:   true,
	})
	ch.AddRoute(CarrierRoute{
		Carrier:    CarrierUnicom,
		Endpoint:   "2.2.2.2:443",
		LatencyMs:  45,
		PacketLoss: 0.01,
		Weight:     100,
		IsActive:   true,
	})

	best := ch.SelectBestCarrier()
	if best == nil || best.Carrier != CarrierUnicom {
		t.Fatalf("expected Unicom as best carrier, got %v", best)
	}

	// Fail Unicom 3 times
	ch.RecordFeedback(CarrierUnicom, 999, false)
	ch.RecordFeedback(CarrierUnicom, 999, false)
	ch.RecordFeedback(CarrierUnicom, 999, false)

	nextBest := ch.SelectBestCarrier()
	if nextBest == nil || nextBest.Carrier != CarrierTelecom {
		t.Fatalf("expected Telecom after failover, got %v", nextBest)
	}
}
