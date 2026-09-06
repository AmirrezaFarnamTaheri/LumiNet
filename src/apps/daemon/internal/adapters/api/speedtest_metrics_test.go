package api

import (
	"math"
	"testing"
	"time"
)

func TestSummarizeSpeedtestLatency(t *testing.T) {
	summary := summarizeSpeedtestLatency([]time.Duration{
		20 * time.Millisecond,
		30 * time.Millisecond,
		25 * time.Millisecond,
		35 * time.Millisecond,
	}, 5)

	if summary.Attempts != 5 || summary.SuccessfulSamples != 4 {
		t.Fatalf("unexpected sample counts: %+v", summary)
	}
	if summary.PingMilliseconds != 20 {
		t.Fatalf("ping = %vms, want 20ms", summary.PingMilliseconds)
	}
	if summary.LatencyMilliseconds != 27.5 {
		t.Fatalf("median latency = %vms, want 27.5ms", summary.LatencyMilliseconds)
	}
	if math.Abs(summary.JitterMilliseconds-(25.0/3.0)) > 0.0001 {
		t.Fatalf("jitter = %vms, want %vms", summary.JitterMilliseconds, 25.0/3.0)
	}
	if summary.PacketLossPercent != 20 {
		t.Fatalf("packet loss = %v%%, want 20%%", summary.PacketLossPercent)
	}
}

func TestSummarizeSpeedtestLatencyAllFailed(t *testing.T) {
	summary := summarizeSpeedtestLatency(nil, 5)
	if summary.PacketLossPercent != 100 || summary.SuccessfulSamples != 0 {
		t.Fatalf("unexpected all-failed summary: %+v", summary)
	}
	if speedtestQualityStable(summary, 100) {
		t.Fatal("all-failed latency samples must never be considered stable")
	}
}

func TestSpeedtestQualityStable(t *testing.T) {
	stable := speedtestLatencySummary{
		Attempts:            5,
		SuccessfulSamples:   5,
		PingMilliseconds:    20,
		LatencyMilliseconds: 24,
		JitterMilliseconds:  10,
		PacketLossPercent:   0,
	}
	if !speedtestQualityStable(stable, 10) {
		t.Fatal("healthy measurements should be stable")
	}

	unstableCases := []speedtestLatencySummary{
		{Attempts: 5, SuccessfulSamples: 4, PacketLossPercent: 20, JitterMilliseconds: 10},
		{Attempts: 5, SuccessfulSamples: 5, PacketLossPercent: 0, JitterMilliseconds: 50},
	}
	for _, candidate := range unstableCases {
		if speedtestQualityStable(candidate, 10) {
			t.Fatalf("unstable measurement accepted: %+v", candidate)
		}
	}
	if speedtestQualityStable(stable, 0.1) {
		t.Fatal("download speed at the minimum threshold must not be considered stable")
	}
}
