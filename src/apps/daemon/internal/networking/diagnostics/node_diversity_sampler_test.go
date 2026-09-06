package diagnostics

import (
	"testing"
)

func TestNodeDiversitySampler(t *testing.T) {
	sampler := NewNodeDiversitySampler()

	sampler.AddNode(DiversityNode{
		NodeID:      "node-cf-us",
		ASN:         13335,
		CountryCode: "US",
		IPPrefix24:  "104.16.1.0",
		LatencyMs:   20,
	})
	sampler.AddNode(DiversityNode{
		NodeID:      "node-cf-de",
		ASN:         13335,
		CountryCode: "DE",
		IPPrefix24:  "104.16.2.0",
		LatencyMs:   35,
	})
	sampler.AddNode(DiversityNode{
		NodeID:      "node-aws-jp",
		ASN:         16509,
		CountryCode: "JP",
		IPPrefix24:  "13.230.1.0",
		LatencyMs:   80,
	})

	metrics := sampler.ComputeDiversityMetrics()
	if metrics.TotalNodes != 3 || metrics.UniqueASNs != 2 || metrics.UniqueCountries != 3 {
		t.Fatalf("unexpected metrics: %+v", metrics)
	}
	if metrics.DiversityScore <= 50.0 {
		t.Fatalf("diversity score should exceed 50.0: got %f", metrics.DiversityScore)
	}

	subset := sampler.SampleDiverseSubset(2)
	if len(subset) != 2 {
		t.Fatalf("expected subset of 2, got %d", len(subset))
	}
	// Must pick from distinct ASNs
	if subset[0] != "node-cf-us" || subset[1] != "node-aws-jp" {
		t.Fatalf("diverse subset did not pick from distinct ASNs: %v", subset)
	}
}
