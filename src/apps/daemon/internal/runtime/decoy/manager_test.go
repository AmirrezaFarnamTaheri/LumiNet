package decoy

import (
	"context"
	"testing"
)

func TestStopIsIdempotent(t *testing.T) {
	manager := New([]string{"http://127.0.0.1:1"}, 1)
	manager.Start(context.Background())
	manager.Stop()
	manager.Stop()
}

func TestNewCopiesTargets(t *testing.T) {
	targets := []string{"https://example.com"}
	manager := New(targets, 120)
	targets[0] = "https://mutated.invalid"
	if manager.targets[0] != "https://example.com" {
		t.Fatalf("manager retained caller slice: %q", manager.targets[0])
	}
}
