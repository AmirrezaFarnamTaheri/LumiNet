package diagnostics

import (
	"testing"
)

func TestScanSubnetNeighbors(t *testing.T) {
	report, err := ScanSubnetNeighbors("192.168.1", 443, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(report.Neighbors) != 5 {
		t.Fatalf("expected 5 neighbors, got %d", len(report.Neighbors))
	}
	if report.Neighbors[0].OpenPort != 443 {
		t.Errorf("expected port 443, got %d", report.Neighbors[0].OpenPort)
	}
}
