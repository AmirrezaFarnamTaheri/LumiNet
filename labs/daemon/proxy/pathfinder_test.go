package proxy

import (
	"testing"
	"time"
)

func TestDijkstraPathfinder(t *testing.T) {
	dp := &DijkstraPathfinder{}

	nodes := []string{"nodeA", "nodeB", "nodeC", "nodeD"}
	matrix := map[string]map[string]time.Duration{
		"nodeA": {
			"nodeB": 50 * time.Millisecond,
			"nodeC": 200 * time.Millisecond,
		},
		"nodeB": {
			"nodeC": 30 * time.Millisecond,
			"nodeD": 100 * time.Millisecond,
		},
		"nodeC": {
			"nodeD": 10 * time.Millisecond,
		},
	}

	// Fastest path should be nodeA -> nodeB -> nodeC -> nodeD
	// Total: 50 + 30 + 10 = 90ms
	// Direct nodeA -> nodeC -> nodeD would be 200 + 10 = 210ms
	// Direct nodeA -> nodeB -> nodeD would be 50 + 100 = 150ms
	path, err := dp.FindBestHopChain("nodeA", "nodeD", nodes, matrix)
	if err != nil {
		t.Fatalf("Pathfinder error: %v", err)
	}

	expected := []string{"nodeA", "nodeB", "nodeC", "nodeD"}
	if len(path) != len(expected) {
		t.Fatalf("Expected path length %d, got %d", len(expected), len(path))
	}

	for i, val := range path {
		if val != expected[i] {
			t.Errorf("Path mismatch at index %d: expected %s, got %s", i, expected[i], val)
		}
	}
}

func TestDijkstraNoPath(t *testing.T) {
	dp := &DijkstraPathfinder{}

	nodes := []string{"nodeA", "nodeB", "nodeC"}
	matrix := map[string]map[string]time.Duration{
		"nodeA": {
			"nodeB": 50 * time.Millisecond,
		},
		// nodeC is isolated
	}

	_, err := dp.FindBestHopChain("nodeA", "nodeC", nodes, matrix)
	if err == nil {
		t.Error("Expected error for unreachable path search, got nil")
	}
}
