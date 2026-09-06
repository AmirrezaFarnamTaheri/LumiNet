package security

import (
	"sync"
	"time"
)

// RelayCircuitState defines circuit breaker states
type RelayCircuitState int

const (
	RelayCircuitClosed RelayCircuitState = iota
	RelayCircuitOpen
	RelayCircuitHalfOpen
)

// RelayEndpointNode stores circuit state for a public relay
type RelayEndpointNode struct {
	ID                  string
	Endpoint            string
	ConsecutiveFailures uint32
	SuccessfulProbes    uint32
	State               RelayCircuitState
	LastStateChange     time.Time
}

// RelayCircuitPolicy governs circuit breaker behavior
type RelayCircuitPolicy struct {
	FailureThreshold    uint32
	HalfOpenProbeNeeded uint32
	Cooldown            time.Duration
}

// RelayRotationCircuitBreaker manages rotating healthy relays with circuit breaking
type RelayRotationCircuitBreaker struct {
	mu           sync.RWMutex
	Policy       RelayCircuitPolicy
	Relays       []*RelayEndpointNode
	CurrentIndex int
}

// NewRelayRotationCircuitBreaker creates a circuit breaker instance
func NewRelayRotationCircuitBreaker(policy RelayCircuitPolicy) *RelayRotationCircuitBreaker {
	return &RelayRotationCircuitBreaker{
		Policy: policy,
	}
}

// RegisterRelay registers a candidate relay
func (cb *RelayRotationCircuitBreaker) RegisterRelay(id, endpoint string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.Relays = append(cb.Relays, &RelayEndpointNode{
		ID:              id,
		Endpoint:        endpoint,
		State:           RelayCircuitClosed,
		LastStateChange: time.Now(),
	})
}

// SelectActiveRelay selects the next available closed or half-open relay
func (cb *RelayRotationCircuitBreaker) SelectActiveRelay(now time.Time) string {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	total := len(cb.Relays)
	if total == 0 {
		return ""
	}

	for i := 0; i < total; i++ {
		idx := (cb.CurrentIndex + i) % total
		relay := cb.Relays[idx]

		if relay.State == RelayCircuitOpen {
			if now.Sub(relay.LastStateChange) >= cb.Policy.Cooldown {
				relay.State = RelayCircuitHalfOpen
				relay.SuccessfulProbes = 0
				relay.LastStateChange = now
				cb.CurrentIndex = idx
				return relay.ID
			}
		} else {
			cb.CurrentIndex = idx
			return relay.ID
		}
	}

	return ""
}

// RecordSuccess records a successful connection
func (cb *RelayRotationCircuitBreaker) RecordSuccess(id string, now time.Time) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	for _, relay := range cb.Relays {
		if relay.ID == id {
			relay.ConsecutiveFailures = 0
			if relay.State == RelayCircuitHalfOpen {
				relay.SuccessfulProbes++
				if relay.SuccessfulProbes >= cb.Policy.HalfOpenProbeNeeded {
					relay.State = RelayCircuitClosed
					relay.LastStateChange = now
				}
			}
			break
		}
	}
}

// RecordFailure records a failed connection and trips circuit if needed
func (cb *RelayRotationCircuitBreaker) RecordFailure(id string, now time.Time) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	for idx, relay := range cb.Relays {
		if relay.ID == id {
			relay.ConsecutiveFailures++
			if relay.State == RelayCircuitClosed && relay.ConsecutiveFailures >= cb.Policy.FailureThreshold {
				relay.State = RelayCircuitOpen
				relay.LastStateChange = now
				cb.CurrentIndex = (idx + 1) % len(cb.Relays)
			} else if relay.State == RelayCircuitHalfOpen {
				relay.State = RelayCircuitOpen
				relay.LastStateChange = now
				cb.CurrentIndex = (idx + 1) % len(cb.Relays)
			}
			break
		}
	}
}
