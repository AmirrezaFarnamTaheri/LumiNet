package proxy

import (
	"net"
	"testing"
)

func TestStaticCidrPool(t *testing.T) {
	pool := NewStaticCidrPool([3]byte{10, 66, 0})
	rec, err := pool.AllocateClient("dev1", "clientPubKey111==")
	if err != nil {
		t.Fatalf("AllocateClient failed: %v", err)
	}

	if rec.AllocatedIP.String() != "10.66.0.2" {
		t.Errorf("expected 10.66.0.2, got %s", rec.AllocatedIP.String())
	}

	if pool.IsKeyRevoked("clientPubKey111==") {
		t.Fatal("key should not be revoked yet")
	}

	if !pool.RevokeClient(net.ParseIP("10.66.0.2")) {
		t.Fatal("RevokeClient should return true")
	}

	if !pool.IsKeyRevoked("clientPubKey111==") {
		t.Fatal("key should be revoked now")
	}
}
