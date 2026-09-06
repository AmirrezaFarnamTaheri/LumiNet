package store

import (
	"context"
	"testing"
)

func TestNodeStore_SaveAndRetrieve(t *testing.T) {
	ctx := context.Background()
	store, err := NewNodeStore(":memory:")
	if err != nil {
		t.Fatalf("failed to open memory db: %v", err)
	}
	defer store.Close()

	err = store.SaveNode(ctx, "vless://user@1.2.3.4:443#Node1", "vless", "1.2.3.4", 443)
	if err != nil {
		t.Fatalf("SaveNode failed: %v", err)
	}

	nodes, err := store.GetHealthyNodes(ctx, 10)
	if err != nil {
		t.Fatalf("GetHealthyNodes failed: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	if nodes[0].Address != "1.2.3.4" || nodes[0].Port != 443 {
		t.Errorf("unexpected node details: %+v", nodes[0])
	}
}
