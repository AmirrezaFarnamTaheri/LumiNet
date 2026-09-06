package security

import (
	"testing"
)

func TestSessionRotationPool(t *testing.T) {
	pool := NewSessionRotationPool(60)
	pool.AddAccount("acc1", "token1", 2)
	pool.AddAccount("acc2", "token2", 1)

	// Uses acc1 (1/2)
	id1, _, ok := pool.AcquireAccount(100)
	if !ok || id1 != "acc1" {
		t.Fatalf("expected acc1, got %s", id1)
	}

	// Uses acc2 (1/1) -> cools down
	id2, _, ok := pool.AcquireAccount(100)
	if !ok || id2 != "acc2" {
		t.Fatalf("expected acc2, got %s", id2)
	}

	// Uses acc1 (2/2) -> cools down
	id3, _, ok := pool.AcquireAccount(100)
	if !ok || id3 != "acc1" {
		t.Fatalf("expected acc1, got %s", id3)
	}

	// Now both in cooldown at t=100
	_, _, ok = pool.AcquireAccount(100)
	if ok {
		t.Fatal("expected no account available at t=100")
	}

	// At t=161, cooldown passed
	id4, _, ok := pool.AcquireAccount(161)
	if !ok || id4 == "" {
		t.Fatalf("expected available account at t=161, got %s", id4)
	}
}
