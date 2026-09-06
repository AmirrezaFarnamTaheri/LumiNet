package worker_rotator

import (
	"errors"
	"sync/atomic"
)

// Rotator balances requests across Cloudflare Worker edge endpoints in round-robin sequence.
type Rotator struct {
	endpoints []string
	idx       uint64
}

// NewRotator creates a Rotator with endpoints.
func NewRotator(endpoints []string) (*Rotator, error) {
	if len(endpoints) == 0 {
		return nil, errors.New("at least one worker endpoint is required")
	}
	return &Rotator{endpoints: endpoints}, nil
}

// Next returns the next worker endpoint URL in round-robin rotation.
func (r *Rotator) Next() string {
	n := atomic.AddUint64(&r.idx, 1)
	return r.endpoints[n%uint64(len(r.endpoints))]
}
