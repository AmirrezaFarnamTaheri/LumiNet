package diagnostics

import "testing"

func TestTransportTruthRequiresSustainedSecondBurst(t *testing.T) {
	cases := []struct {
		name      string
		req       TransportTruthRequest
		verdict   string
		connected bool
	}{
		{"no handshake", TransportTruthRequest{HandshakeOK: false, BurstSize: 10}, "handshake-failed", false},
		{"handshake only", TransportTruthRequest{HandshakeOK: true, BurstSize: 10}, "handshake-only", false},
		{"one burst", TransportTruthRequest{HandshakeOK: true, BurstSize: 10, FirstBurstSuccesses: 10}, "transient", false},
		{"weak second burst", TransportTruthRequest{HandshakeOK: true, BurstSize: 10, FirstBurstSuccesses: 10, SecondBurstSuccesses: 3}, "torn-down", false},
		{"durable", TransportTruthRequest{HandshakeOK: true, BurstSize: 10, FirstBurstSuccesses: 9, SecondBurstSuccesses: 8}, "durable", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := BuildTransportTruthPlan(tc.req)
			if err != nil {
				t.Fatal(err)
			}
			if p.Verdict != tc.verdict || p.Connected != tc.connected {
				t.Fatalf("plan=%+v", p)
			}
		})
	}
}

func TestTransportTruthKeepsAdvertisedAndMeasuredCountriesSeparate(t *testing.T) {
	p, err := BuildTransportTruthPlan(TransportTruthRequest{HandshakeOK: true, BurstSize: 10, FirstBurstSuccesses: 10, SecondBurstSuccesses: 10, AdvertisedCountry: "us", MeasuredEgressCountry: "DE"})
	if err != nil {
		t.Fatal(err)
	}
	if p.AdvertisedCountry != "US" || p.MeasuredEgressCountry != "DE" || p.LocationVerdict != "mismatch" {
		t.Fatalf("plan=%+v", p)
	}
	if !p.Connected {
		t.Fatal("durable traffic lost because location mismatched")
	}
}

func TestTransportTruthBoundsEvidence(t *testing.T) {
	if _, err := BuildTransportTruthPlan(TransportTruthRequest{HandshakeOK: true, BurstSize: 0}); err == nil {
		t.Fatal("zero burst size accepted")
	}
	if _, err := BuildTransportTruthPlan(TransportTruthRequest{HandshakeOK: true, BurstSize: 10, FirstBurstSuccesses: 11}); err == nil {
		t.Fatal("impossible burst accepted")
	}
	if _, err := BuildTransportTruthPlan(TransportTruthRequest{HandshakeOK: true, BurstSize: 10, MinimumDeliveryPct: 101}); err == nil {
		t.Fatal("invalid threshold accepted")
	}
	if _, err := BuildTransportTruthPlan(TransportTruthRequest{HandshakeOK: true, BurstSize: 10, AdvertisedCountry: "USA"}); err == nil {
		t.Fatal("invalid country accepted")
	}
}
