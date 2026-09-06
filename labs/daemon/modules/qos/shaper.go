package qos

import (
	"context"

	"github.com/maybeknott/luminet/internal/netutil"
	"golang.org/x/time/rate"
)

// Shaper enforces bandwidth limits using token bucket rate limiting.
type Shaper struct {
	limiter *rate.Limiter
}

// NewShaper creates a new rate limiter with bytes-per-second target.
func NewShaper(bytesPerSec int) *Shaper {
	if bytesPerSec <= 0 {
		bytesPerSec = int(netutil.DefaultUnlimitedPolicy().BytesPerSecond)
	}
	policy, _ := (netutil.RatePolicy{BytesPerSecond: int64(bytesPerSec), BurstBytes: int64(bytesPerSec / 8)}).Normalize()
	burst := int(policy.BurstBytes)
	if burst < 4096 {
		burst = 4096
	}
	return &Shaper{
		limiter: rate.NewLimiter(rate.Limit(policy.BytesPerSecond), burst),
	}
}

// WaitN blocks until n bytes are allowed by the shaper.
func (s *Shaper) WaitN(ctx context.Context, n int) error {
	return s.limiter.WaitN(ctx, n)
}
