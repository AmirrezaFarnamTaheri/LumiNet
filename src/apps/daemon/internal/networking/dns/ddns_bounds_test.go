package dns

import (
	"bytes"
	"testing"
)

func TestDecodeBoundedDDNSJSONRejectsOversize(t *testing.T) {
	var dst map[string]any
	if err := decodeBoundedDDNSJSON(bytes.NewReader(make([]byte, maxDDNSAPIResponseBytes+1)), &dst); err == nil {
		t.Fatal("expected oversized DDNS response to be rejected")
	}
}
