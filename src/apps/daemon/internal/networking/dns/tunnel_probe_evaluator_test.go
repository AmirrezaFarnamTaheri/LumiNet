package dns

import (
	"testing"
)

func TestComputeProbeMetrics(t *testing.T) {
	tcp := TCPProbeResult{
		Success: true,
		Attempts: []AttemptMetric{
			{Success: true, DurationMs: 50},
			{Success: true, DurationMs: 70},
			{Success: true, DurationMs: 90},
		},
		MedianRTTMs: 70,
		Consistency: 1.0,
	}
	udp := UDPProbeResult{
		Reachable: true,
		Attempts: []AttemptMetric{
			{Success: true, DurationMs: 60},
		},
	}
	dns := DNSProbeResult{
		UDPResponsive: true,
		TCPResponsive: true,
		Answers:       []string{"1.1.1.1"},
		Attempts: []AttemptMetric{
			{Success: true, DurationMs: 80},
		},
	}

	metrics := ComputeProbeMetrics(tcp, udp, dns)
	if metrics.RTTMs != 70 {
		t.Fatalf("expected RTTMs 70, got %d", metrics.RTTMs)
	}
	if metrics.JitterMs != 14 {
		t.Fatalf("expected JitterMs 14, got %d", metrics.JitterMs)
	}
	if metrics.PacketLossEstimate != 0.0 {
		t.Fatalf("expected PacketLossEstimate 0.0, got %f", metrics.PacketLossEstimate)
	}
	if metrics.StabilityPercent != 100.0 {
		t.Fatalf("expected StabilityPercent 100.0, got %f", metrics.StabilityPercent)
	}
}

func TestScoreProbeResult_TunnelReady(t *testing.T) {
	tcp := TCPProbeResult{
		Success:     true,
		Attempts:    []AttemptMetric{{Success: true, DurationMs: 40}},
		MedianRTTMs: 42,
		Consistency: 1.0,
	}
	tls := TLSProbeResult{
		Success:     true,
		HandshakeMs: 80,
		Version:     "TLS 1.3",
		Verified:    true,
	}
	http := HTTPProbeResult{
		Success: true,
		Probes: []HTTPProbeItem{
			{Method: "GET", URL: "https://example.com/", StatusCode: 200, DurationMs: 60},
		},
	}
	ws := WSProbeResult{
		Success:    true,
		StatusCode: 101,
		DurationMs: 70,
	}
	quic := QUICProbeResult{
		Success:     true,
		HandshakeMs: 65,
		ALPN:        "h3",
	}
	dns := DNSProbeResult{
		UDPResponsive: true,
		TCPResponsive: true,
		Answers:       []string{"1.1.1.1"},
	}
	metrics := ProbeMetrics{
		RTTMs:            42,
		JitterMs:         10,
		StabilityPercent: 98.0,
	}

	score := ScoreProbeResult(tcp, tls, http, ws, quic, dns, metrics)
	if score.Classification != "Tunnel Ready" {
		t.Fatalf("expected 'Tunnel Ready', got %s", score.Classification)
	}
	if score.Grade != "A+" {
		t.Fatalf("expected grade 'A+', got %s", score.Grade)
	}
	if score.FalsePositive {
		t.Fatalf("did not expect false positive")
	}
	if score.Numeric < 94 {
		t.Fatalf("expected numeric score >= 94, got %d", score.Numeric)
	}
}

func TestScoreProbeResult_FalsePositive_Spoofing(t *testing.T) {
	// TCP SYN-ACK received, but higher application layers blocked
	tcp := TCPProbeResult{
		Success:     true,
		Attempts:    []AttemptMetric{{Success: true, DurationMs: 20}},
		MedianRTTMs: 20,
		Consistency: 1.0,
	}
	tls := TLSProbeResult{Success: false}
	http := HTTPProbeResult{Success: false}
	ws := WSProbeResult{Success: false}
	quic := QUICProbeResult{Success: false}
	dns := DNSProbeResult{UDPResponsive: false, TCPResponsive: false}
	metrics := ProbeMetrics{RTTMs: 20, JitterMs: 2, StabilityPercent: 100.0}

	score := ScoreProbeResult(tcp, tls, http, ws, quic, dns, metrics)
	if !score.FalsePositive {
		t.Fatalf("expected false positive detection for spoofed TCP ACK")
	}
	if score.Classification != "False Positive" {
		t.Fatalf("expected classification 'False Positive', got %s", score.Classification)
	}
}

func TestScoreProbeResult_FalsePositive_InconsistentTCP(t *testing.T) {
	tcp := TCPProbeResult{
		Success:     true,
		Attempts:    []AttemptMetric{{Success: true, DurationMs: 20}},
		Consistency: 0.33,
	}
	score := ScoreProbeResult(tcp, TLSProbeResult{Success: true}, HTTPProbeResult{}, WSProbeResult{}, QUICProbeResult{}, DNSProbeResult{}, ProbeMetrics{})
	if !score.FalsePositive {
		t.Fatalf("expected false positive detection for inconsistent TCP")
	}
}

func TestParseCloudflareTrace(t *testing.T) {
	trace := "fl=123f45\nip=198.51.100.42\nloc=us\nts=1690000000\n"
	ip, loc := ParseCloudflareTrace(trace)
	if ip != "198.51.100.42" {
		t.Fatalf("expected ip '198.51.100.42', got %s", ip)
	}
	if loc != "US" {
		t.Fatalf("expected loc 'US', got %s", loc)
	}
}
