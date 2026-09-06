package transport

import (
	"testing"
)

func TestZeroRttSessionCache(t *testing.T) {
	cache := NewZeroRttSessionCache()
	cache.StoreTicket("edge.luminet.net", []byte("ticket-val"), "h3", 1000, 300)

	valid := cache.GetValidTicket("edge.luminet.net", 1100)
	if valid == nil || string(valid.TicketBytes) != "ticket-val" {
		t.Fatalf("expected valid ticket")
	}

	expired := cache.GetValidTicket("edge.luminet.net", 1400)
	if expired != nil {
		t.Fatalf("expected ticket to be expired")
	}

	nonce := []byte("session-nonce-1")
	if !cache.CheckAndConsumeNonce(nonce) {
		t.Fatalf("first check should succeed")
	}
	if cache.CheckAndConsumeNonce(nonce) {
		t.Fatalf("duplicate check should fail")
	}
}
