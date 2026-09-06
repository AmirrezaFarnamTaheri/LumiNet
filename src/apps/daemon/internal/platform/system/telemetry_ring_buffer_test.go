package system

import "testing"

func TestTelemetryRingBufferWrapsChronologically(t *testing.T) {
	buffer := NewTelemetryRingBuffer(2)
	buffer.Append("one")
	buffer.Append("two")
	buffer.Append("three")
	got := buffer.Snapshot()
	if len(got) != 2 || got[0] != "two" || got[1] != "three" {
		t.Fatalf("Snapshot = %v, want [two three]", got)
	}
}

func TestTelemetryRingBufferDefaultsInvalidCapacity(t *testing.T) {
	buffer := NewTelemetryRingBuffer(0)
	buffer.Append("entry")
	got := buffer.Snapshot()
	if len(got) != 1 || got[0] != "entry" {
		t.Fatalf("Snapshot = %v, want [entry]", got)
	}
}
