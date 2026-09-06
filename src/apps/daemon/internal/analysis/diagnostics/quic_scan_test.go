package diagnostics

import (
	"strings"
	"testing"
)

func TestScanQuicInitialRejectsShortDatagram(t *testing.T) {
	_, err := ScanQuicInitial("1.1.1.1:443", make([]byte, 5), false)
	if err == nil {
		t.Fatal("expected error for short datagram, got nil")
	}
}

func TestScanQuicInitialRejectsBadAddr(t *testing.T) {
	_, err := ScanQuicInitial("not-an-addr", make([]byte, 64), false)
	if err == nil {
		t.Fatal("expected error for malformed addr, got nil")
	}
	if !strings.Contains(err.Error(), "quic scan") {
		t.Fatalf("error should be wrapped with quic scan context, got: %v", err)
	}
}
