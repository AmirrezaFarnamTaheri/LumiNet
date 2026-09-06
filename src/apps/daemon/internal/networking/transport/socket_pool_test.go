package transport

import (
	"testing"
)

func TestSocketPoolSupervisor(t *testing.T) {
	pool := NewSocketPoolSupervisor()
	pool.RegisterSocket("s1", "1.1.1.1:443")
	pool.RegisterSocket("s2", "2.2.2.2:443")

	act := pool.ActiveSocket()
	if act == nil || act.ID != "s1" {
		t.Fatalf("expected s1 as active, got %+v", act)
	}

	// Fail s1
	pool.RecordHeartbeat("s1", 500, false)
	act2 := pool.ActiveSocket()
	if act2 == nil || act2.ID != "s2" {
		t.Fatalf("expected failover to s2, got %+v", act2)
	}
}
