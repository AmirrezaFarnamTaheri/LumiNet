package security

import (
	"testing"
	"time"
)

func TestRelayRotationCircuitBreaker(t *testing.T) {
	policy := RelayCircuitPolicy{
		FailureThreshold:    2,
		HalfOpenProbeNeeded: 2,
		Cooldown:            5 * time.Second,
	}
	cb := NewRelayRotationCircuitBreaker(policy)

	cb.RegisterRelay("relay-1", "1.1.1.1:443")
	cb.RegisterRelay("relay-2", "2.2.2.2:443")

	now := time.Now()
	if active := cb.SelectActiveRelay(now); active != "relay-1" {
		t.Fatalf("expected initial relay-1, got %s", active)
	}

	// 2 failures trip relay-1
	cb.RecordFailure("relay-1", now)
	cb.RecordFailure("relay-1", now)

	// Rotates to relay-2
	if active := cb.SelectActiveRelay(now); active != "relay-2" {
		t.Fatalf("expected rotation to relay-2, got %s", active)
	}

	// Fail relay-2 as well
	cb.RecordFailure("relay-2", now)
	cb.RecordFailure("relay-2", now)

	// After cooldown, relay-1 becomes half-open and selected
	later := now.Add(6 * time.Second)
	if active := cb.SelectActiveRelay(later); active != "relay-1" {
		t.Fatalf("expected half-open relay-1, got %s", active)
	}

	// 2 successful probes close circuit
	cb.RecordSuccess("relay-1", later)
	cb.RecordSuccess("relay-1", later)

	if cb.Relays[0].State != RelayCircuitClosed {
		t.Fatalf("expected relay-1 to recover to Closed")
	}
}
