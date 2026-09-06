package api

import (
	"math"
	"sort"
	"time"
)

type speedtestLatencySummary struct {
	Attempts            int
	SuccessfulSamples   int
	PingMilliseconds    float64
	LatencyMilliseconds float64
	JitterMilliseconds  float64
	PacketLossPercent   float64
}

func summarizeSpeedtestLatency(samples []time.Duration, attempts int) speedtestLatencySummary {
	if attempts < len(samples) {
		attempts = len(samples)
	}
	if attempts < 0 {
		attempts = 0
	}

	summary := speedtestLatencySummary{
		Attempts:          attempts,
		SuccessfulSamples: len(samples),
	}
	if attempts > 0 {
		summary.PacketLossPercent = float64(attempts-len(samples)) / float64(attempts) * 100
	}
	if len(samples) == 0 {
		return summary
	}

	milliseconds := make([]float64, len(samples))
	for i, sample := range samples {
		milliseconds[i] = float64(sample) / float64(time.Millisecond)
	}

	sorted := append([]float64(nil), milliseconds...)
	sort.Float64s(sorted)
	summary.PingMilliseconds = sorted[0]
	if len(sorted)%2 == 1 {
		summary.LatencyMilliseconds = sorted[len(sorted)/2]
	} else {
		mid := len(sorted) / 2
		summary.LatencyMilliseconds = (sorted[mid-1] + sorted[mid]) / 2
	}

	if len(milliseconds) > 1 {
		var totalDelta float64
		for i := 1; i < len(milliseconds); i++ {
			totalDelta += math.Abs(milliseconds[i] - milliseconds[i-1])
		}
		summary.JitterMilliseconds = totalDelta / float64(len(milliseconds)-1)
	}

	return summary
}

func speedtestQualityStable(summary speedtestLatencySummary, downloadMbps float64) bool {
	return summary.SuccessfulSamples > 0 &&
		summary.PacketLossPercent < 5 &&
		summary.JitterMilliseconds < 50 &&
		downloadMbps > 0.1
}
