package tui

import (
	"testing"
)

func TestTUI_NewModel(t *testing.T) {
	m := NewModel(nil, "test-data", "127.0.0.1", 8470, "test-api-key")
	if m.dataDir != "test-data" || m.host != "127.0.0.1" || m.port != 8470 {
		t.Fatalf("constructor did not preserve daemon endpoint configuration: %#v", m)
	}
	if m.totalRamGb <= 0 {
		t.Fatalf("constructor must initialize a positive memory baseline, got %f", m.totalRamGb)
	}
}
