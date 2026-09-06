package transport

import (
	"testing"
)

func TestAmneziaObfsParameters(t *testing.T) {
	params := DefaultAmneziaParams()
	if err := params.Validate(); err != nil {
		t.Fatalf("default params should be valid: %v", err)
	}

	lines := []string{
		"Jc = 5",
		"Jmin = 50",
		"Jmax = 80",
		"S1 = 64",
		"S2 = 64",
		"H1 = 0x12345678",
		"H2 = 0x87654321",
	}

	for _, l := range lines {
		if err := params.ParseAmneziaConfigLine(l); err != nil {
			t.Fatalf("failed to parse %s: %v", l, err)
		}
	}

	if params.Jc != 5 || params.Jmin != 50 || params.Jmax != 80 || params.S1 != 64 || params.H1 != 0x12345678 {
		t.Fatalf("parsed parameters mismatch")
	}

	if err := params.Validate(); err != nil {
		t.Fatalf("parsed params should be valid: %v", err)
	}
}
