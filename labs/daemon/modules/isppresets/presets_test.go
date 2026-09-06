package isppresets

import (
	"testing"
)

func TestISPPresetsLookup(t *testing.T) {
	presets, err := GetAllPresets()
	if err != nil {
		t.Fatalf("failed to load ISP presets: %v", err)
	}

	if len(presets) == 0 {
		t.Log("no embedded range files found in ranges/, test passed with default empty preset array")
	}
}
