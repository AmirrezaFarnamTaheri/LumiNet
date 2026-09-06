package dns

import (
	"bytes"
	"testing"
)

func TestReadBoundedDNSBodyRejectsOversize(t *testing.T) {
	if _, err := readBoundedDNSBody(bytes.NewReader(make([]byte, maxDNSHTTPBodyBytes+1))); err == nil {
		t.Fatal("oversized DNS HTTP body was accepted")
	}
}

func TestReadBoundedDNSBodyAcceptsMaximum(t *testing.T) {
	body, err := readBoundedDNSBody(bytes.NewReader(make([]byte, maxDNSHTTPBodyBytes)))
	if err != nil {
		t.Fatalf("maximum DNS HTTP body rejected: %v", err)
	}
	if int64(len(body)) != maxDNSHTTPBodyBytes {
		t.Fatalf("body length = %d, want %d", len(body), maxDNSHTTPBodyBytes)
	}
}
