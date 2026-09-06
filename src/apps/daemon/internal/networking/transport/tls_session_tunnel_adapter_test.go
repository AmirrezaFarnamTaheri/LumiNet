package transport

import (
	"bytes"
	"testing"
	"time"
)

func TestTlsSessionTunnelAdapter(t *testing.T) {
	adapter := NewTlsSessionTunnelAdapter()

	ticketID := GenerateRandomTicketID()
	secret := []byte("master-secret-key-32-bytes-long!")
	adapter.StoreTicket("vpn.internal.corp", ticketID, secret, 16384, 10*time.Minute)

	// Retrieve
	ticket, ok := adapter.RetrieveTicket("vpn.internal.corp")
	if !ok {
		t.Fatalf("expected ticket retrieval to succeed")
	}
	if ticket.TicketID != ticketID {
		t.Fatalf("ticket ID mismatch: expected %s, got %s", ticketID, ticket.TicketID)
	}

	// Missing domain
	if _, ok := adapter.RetrieveTicket("unknown.domain.com"); ok {
		t.Fatalf("expected missing domain retrieval to fail")
	}

	// Frame and unframe 0-RTT early data
	payload := []byte("QUIC_0RTT_CLIENT_PAYLOAD")
	framed, err := adapter.FrameEarlyData(ticketID, payload)
	if err != nil {
		t.Fatalf("failed to frame early data: %v", err)
	}

	recTicketID, recPayload, err := adapter.UnframeEarlyData(framed)
	if err != nil {
		t.Fatalf("failed to unframe early data: %v", err)
	}
	if recTicketID != ticketID {
		t.Fatalf("unframed ticket ID mismatch")
	}
	if !bytes.Equal(recPayload, payload) {
		t.Fatalf("unframed payload mismatch")
	}
}
