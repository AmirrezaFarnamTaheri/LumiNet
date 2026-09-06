package p2p

import (
	"testing"
)

func TestRoutingTableInsertAndFind(t *testing.T) {
	pub, _, selfID, err := GenerateNodeID()
	if err != nil {
		t.Fatalf("failed to generate self node ID: %v", err)
	}

	rt := NewRoutingTable(pub)

	// Generate 5 peers and insert them
	for i := 0; i < 5; i++ {
		pPub, _, pID, err := GenerateNodeID()
		if err != nil {
			t.Fatalf("failed to generate peer node ID: %v", err)
		}
		inserted := rt.Insert(PeerInfo{
			ID:      pID,
			Address: "127.0.0.1:9000",
			PubKey:  pPub,
		})
		if !inserted {
			t.Errorf("failed to insert peer %d", i)
		}
	}

	closest := rt.FindClosest(selfID, 10)
	if len(closest) == 0 {
		t.Error("expected at least 1 peer, got 0")
	}
}
