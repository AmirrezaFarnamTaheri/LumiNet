package geoip

import (
	"bytes"
	"testing"
)

func TestDecodeBoundedGeoIPJSONRejectsOversize(t *testing.T) {
	var dst map[string]any
	if err := decodeBoundedGeoIPJSON(bytes.NewReader(make([]byte, maxGeoIPResponseBytes+1)), &dst); err == nil {
		t.Fatal("expected oversized geoip response to be rejected")
	}
}
