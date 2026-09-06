package diagnostics

import (
	"net"
	"testing"
)

func TestQuicObserverService_PrefilterRejectsNonQuic(t *testing.T) {
	called := false
	s := NewQuicObserverService(func(QuicScanResult) { called = true })

	// Short header (bit 7 clear) — must not even attempt the native scan.
	short := make([]byte, 1300)
	short[0] = 0x40
	s.ObservePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 443}, short)

	// Version negotiation (version 0) — rejected.
	vn := make([]byte, 1300)
	vn[0] = 0xc0
	s.ObservePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 443}, vn)

	a, f, fl := s.Counters()
	if a != 0 || f != 0 || fl != 0 {
		t.Fatalf("counters = (%d,%d,%d), want all zero", a, f, fl)
	}
	if called {
		t.Fatal("callback fired for non-QUIC datagram")
	}
}

func TestQuicObserverService_DisabledShortCircuits(t *testing.T) {
	s := NewQuicObserverService(nil)
	s.SetEnabled(false)
	plausible := make([]byte, 1300)
	plausible[0] = 0xc3
	plausible[1] = 0x00
	plausible[2] = 0x00
	plausible[3] = 0x00
	plausible[4] = 0x01
	s.ObservePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 443}, plausible)
	if a, _, _ := s.Counters(); a != 0 {
		t.Fatalf("attempts = %d, want 0 while disabled", a)
	}
}

func TestQuicObserverService_PlausibleDatagramDoesNotPanic(t *testing.T) {
	// In degraded (no-native-core) builds the scan returns an error and
	// must be counted as a failure, never panic the packet path.
	s := NewQuicObserverService(nil)
	plausible := make([]byte, 1300)
	plausible[0] = 0xc3
	plausible[1] = 0x00
	plausible[2] = 0x00
	plausible[3] = 0x00
	plausible[4] = 0x01
	s.ObservePacket(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 443}, plausible)
	a, _, fl := s.Counters()
	if a != 1 {
		t.Fatalf("attempts = %d, want 1", a)
	}
	if fl != 1 {
		t.Fatalf("failures = %d, want 1 (native core unavailable in test build)", fl)
	}
}
