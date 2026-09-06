package worker_rotator

import (
	"testing"
)

func TestWorkerRotatorRoundRobin(t *testing.T) {
	endpoints := []string{
		"https://worker-1.edge.workers.dev",
		"https://worker-2.edge.workers.dev",
		"https://worker-3.edge.workers.dev",
	}

	rot, err := NewRotator(endpoints)
	if err != nil {
		t.Fatalf("failed to create rotator: %v", err)
	}

	ep1 := rot.Next()
	ep2 := rot.Next()
	ep3 := rot.Next()

	if ep1 == ep2 || ep2 == ep3 {
		t.Error("expected round-robin rotation across distinct worker endpoints")
	}
}
