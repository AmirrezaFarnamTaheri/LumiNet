package transport

import (
	"bytes"
	"testing"
)

func TestSniDecoyInjector(t *testing.T) {
	injector := NewSniDecoyInjector("cloudflare.com")
	realPkt := []byte{0x16, 0x03, 0x01, 0x00, 0x50, 0x01}
	pkts := injector.InjectDecoy(realPkt)
	if len(pkts) != 2 {
		t.Fatalf("expected 2 packets")
	}
	if !bytes.Contains(pkts[0], []byte("cloudflare.com")) {
		t.Errorf("expected decoy packet to contain cloudflare.com")
	}
	if !bytes.Equal(pkts[1], realPkt) {
		t.Errorf("expected second packet to be real packet")
	}
}
