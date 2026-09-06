package scanner

import (
	"context"
	"testing"
)

func TestSynScanner_Local(t *testing.T) {
	scanner := NewSynScanner("127.0.0.1", []int{80, 443})
	results, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}

	for _, res := range results {
		if res.Status != PortClosed && res.Status != PortFiltered {
			t.Errorf("expected closed/filtered status for port %d, got %s", res.Port, res.Status)
		}
	}
}
