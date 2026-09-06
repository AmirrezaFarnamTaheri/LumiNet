package backhaul

import (
	"net"
	"testing"
)

func TestBackhaulMuxRoundRobin(t *testing.T) {
	mux := NewBackhaulMux()

	c1, c2 := net.Pipe()
	c3, c4 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	defer c3.Close()
	defer c4.Close()

	mux.AddConn(c1)
	mux.AddConn(c3)

	if mux.ActiveCount() != 2 {
		t.Fatalf("expected 2 connections, got %d", mux.ActiveCount())
	}

	n1, err := mux.NextConn()
	if err != nil {
		t.Fatalf("failed to get next connection: %v", err)
	}

	n2, err := mux.NextConn()
	if err != nil {
		t.Fatalf("failed to get next connection: %v", err)
	}

	if n1 == n2 {
		t.Error("expected round-robin rotation between different connections")
	}

	mux.RemoveConn(c1)
	if mux.ActiveCount() != 1 {
		t.Errorf("expected 1 connection after removal, got %d", mux.ActiveCount())
	}
}
