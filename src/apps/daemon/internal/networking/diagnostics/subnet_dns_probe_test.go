package diagnostics

import (
	"testing"
)

func TestSubnetDnsScanner(t *testing.T) {
	scanner := NewSubnetDnsScanner("93.184.216.34")

	scanner.RecordProbe("1.1.1.1", 15.0, "93.184.216.34", false)
	scanner.RecordProbe("10.0.0.1", 5.0, "10.10.34.34", false) // poisoned
	scanner.RecordProbe("8.8.8.8", 0.0, "", true)              // timeout

	clean, err := scanner.SelectCleanFastest()
	if err != nil {
		t.Fatalf("SelectCleanFastest failed: %v", err)
	}

	if clean.ServerIP != "1.1.1.1" || clean.ResponseTimeMs != 15.0 {
		t.Fatalf("expected 1.1.1.1, got %+v", clean)
	}
}
