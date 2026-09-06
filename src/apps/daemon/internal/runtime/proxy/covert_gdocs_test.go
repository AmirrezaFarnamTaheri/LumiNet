package proxy

import (
	"context"
	"errors"
	"testing"
)

func TestGDocsTransportRejectsMissingCredentials(t *testing.T) {
	for _, tc := range []struct{ folder, token string }{{"", "token"}, {"folder", ""}} {
		if _, err := NewGDocsTransport(tc.folder, tc.token); err == nil {
			t.Fatalf("NewGDocsTransport(%q, <token=%t>) accepted incomplete credentials", tc.folder, tc.token != "")
		}
	}
}

func TestGDocsVirtualConnectionUsesCallerContext(t *testing.T) {
	transport, err := NewGDocsTransport("folder", "token")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn := transport.VirtualConnection(ctx, "session")
	_, err = conn.Write([]byte("payload"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Write error = %v, want context.Canceled", err)
	}
}
