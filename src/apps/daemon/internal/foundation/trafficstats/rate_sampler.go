package trafficstats

import (
	"sync"
	"time"
)

// Rates is a point-in-time transfer rate derived from monotonic byte counters.
type Rates struct {
	RXBytesPerSecond float64
	TXBytesPerSecond float64
}

// RateSampler converts cumulative upload/download counters into per-second rates.
// A sample is valid only after a prior baseline exists for monotonic counters.
type RateSampler struct {
	mu          sync.Mutex
	initialized bool
	at          time.Time
	upload      uint64
	download    uint64
}

func NewRateSampler() *RateSampler { return &RateSampler{} }

// Sample derives rates from cumulative counters. ok is false for the first
// sample, non-positive elapsed time, or after a counter reset/decrease.
func (s *RateSampler) Sample(now time.Time, uploadBytes, downloadBytes uint64) (rates Rates, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.initialized {
		s.initialized = true
		s.at = now
		s.upload = uploadBytes
		s.download = downloadBytes
		return Rates{}, false
	}

	elapsed := now.Sub(s.at)
	if elapsed <= 0 {
		return Rates{}, false
	}

	if uploadBytes < s.upload || downloadBytes < s.download {
		s.at = now
		s.upload = uploadBytes
		s.download = downloadBytes
		return Rates{}, false
	}

	seconds := elapsed.Seconds()
	rates = Rates{
		RXBytesPerSecond: float64(downloadBytes-s.download) / seconds,
		TXBytesPerSecond: float64(uploadBytes-s.upload) / seconds,
	}
	s.at = now
	s.upload = uploadBytes
	s.download = downloadBytes
	return rates, true
}
