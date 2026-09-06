package telemetry

import (
	"testing"
)

func TestRingBuffer_PushAndSnapshot(t *testing.T) {
	rb := NewRingBuffer(5)

	rb.Push(45.2, 100, 200)
	rb.Push(32.1, 150, 300)
	rb.Push(28.7, 200, 400)

	if rb.Count() != 3 {
		t.Fatalf("expected count 3, got %d", rb.Count())
	}

	snapshot := rb.Snapshot(3)
	if len(snapshot) != 3 {
		t.Fatalf("expected snapshot len 3, got %d", len(snapshot))
	}

	if snapshot[0].LatencyMs != 45.2 || snapshot[2].LatencyMs != 28.7 {
		t.Errorf("unexpected snapshot data ordering: %+v", snapshot)
	}
}

func TestRingBuffer_Overflow(t *testing.T) {
	rb := NewRingBuffer(3)

	rb.Push(10.0, 1, 1)
	rb.Push(20.0, 2, 2)
	rb.Push(30.0, 3, 3)
	rb.Push(40.0, 4, 4) // Overwrites 10.0

	if rb.Count() != 3 {
		t.Fatalf("expected count 3 after overflow, got %d", rb.Count())
	}

	snapshot := rb.Snapshot(3)
	if snapshot[0].LatencyMs != 20.0 || snapshot[2].LatencyMs != 40.0 {
		t.Errorf("unexpected overflow snapshot data: %+v", snapshot)
	}
}
