package transport

import (
	"testing"
)

func TestReverseTunnelRelay(t *testing.T) {
	relay := NewReverseTunnelRelay(5)

	id, err := relay.OpenSession("198.51.100.30:45000", "10.0.0.5:8080")
	if err != nil {
		t.Fatalf("failed to open session: %v", err)
	}

	if relay.ActiveSessionsCount() != 1 {
		t.Fatalf("expected 1 active session, got %d", relay.ActiveSessionsCount())
	}

	if err := relay.ForwardData(id, 1024, 2048); err != nil {
		t.Fatalf("failed to forward data: %v", err)
	}

	// Close session
	if !relay.CloseSession(id) {
		t.Fatalf("expected close session to succeed")
	}
	if relay.ActiveSessionsCount() != 0 {
		t.Fatalf("expected 0 active sessions after close")
	}
}
