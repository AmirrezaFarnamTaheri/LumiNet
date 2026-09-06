package proxyconfig

import (
	"encoding/json"
	"fmt"
	"strings"
)

// MaxFinalMaskBytes is an absolute ceiling for share-controlled Finalmask JSON.
const MaxFinalMaskBytes = 16 * 1024

// DecodeFinalMask validates bounded object-only JSON and returns a generic map
// suitable for Xray streamSettings.finalmask.
func DecodeFinalMask(raw string) (map[string]interface{}, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if len(raw) > MaxFinalMaskBytes {
		return nil, fmt.Errorf("finalmask exceeds %d bytes", MaxFinalMaskBytes)
	}
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("invalid finalmask JSON: %w", err)
	}
	if out == nil {
		return nil, fmt.Errorf("finalmask must be a JSON object")
	}
	return out, nil
}
