package trafficstats

import (
	"testing"
	"time"
)

func TestRateSamplerDerivesRatesFromCounterDeltas(t *testing.T) {
	sampler := NewRateSampler()
	start := time.Unix(100, 0)
	if _, ok := sampler.Sample(start, 100, 200); ok {
		t.Fatal("first sample should establish a baseline, not publish a rate")
	}

	rates, ok := sampler.Sample(start.Add(2*time.Second), 500, 1200)
	if !ok {
		t.Fatal("second monotonic sample should produce a rate")
	}
	if rates.TXBytesPerSecond != 200 {
		t.Fatalf("TX rate = %v, want 200", rates.TXBytesPerSecond)
	}
	if rates.RXBytesPerSecond != 500 {
		t.Fatalf("RX rate = %v, want 500", rates.RXBytesPerSecond)
	}
}

func TestRateSamplerResetsBaselineWhenCountersDecrease(t *testing.T) {
	sampler := NewRateSampler()
	start := time.Unix(200, 0)
	sampler.Sample(start, 1000, 2000)
	if _, ok := sampler.Sample(start.Add(time.Second), 20, 30); ok {
		t.Fatal("counter reset must not be interpreted as a transfer spike")
	}

	rates, ok := sampler.Sample(start.Add(2*time.Second), 120, 230)
	if !ok {
		t.Fatal("sample after reset baseline should produce a rate")
	}
	if rates.TXBytesPerSecond != 100 || rates.RXBytesPerSecond != 200 {
		t.Fatalf("rates after reset = %+v, want TX=100 RX=200", rates)
	}
}

func TestRateSamplerRejectsNonPositiveElapsedTime(t *testing.T) {
	sampler := NewRateSampler()
	at := time.Unix(300, 0)
	sampler.Sample(at, 10, 10)
	if _, ok := sampler.Sample(at, 20, 20); ok {
		t.Fatal("zero elapsed time must not produce a rate")
	}
	rates, ok := sampler.Sample(at.Add(time.Second), 120, 220)
	if !ok {
		t.Fatal("sampler should recover after an invalid time sample")
	}
	if rates.TXBytesPerSecond != 110 || rates.RXBytesPerSecond != 210 {
		t.Fatalf("recovered rates = %+v, want TX=110 RX=210", rates)
	}
}
