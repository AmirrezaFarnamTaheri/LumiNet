package proxy

import (
	"context"
	"strings"
	"testing"
)

func TestResidentialEgressRequiresExplicitAddress(t *testing.T) {
	mgr := &EvasionTunnelManager{}
	conn, err := mgr.dialResidentialEgress(context.Background(), "example.com", 443, "")
	if conn != nil {
		_ = conn.Close()
		t.Fatal("empty residential egress unexpectedly returned a connection")
	}
	if err == nil || !strings.Contains(err.Error(), "explicit SOCKS5 egress address") {
		t.Fatalf("empty residential egress error = %v", err)
	}
}
