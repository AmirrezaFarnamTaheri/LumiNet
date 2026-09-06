package proxy

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestProxyCloudManager(t *testing.T) {
	// Setup a mock TCP server to measure latency
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen TCP: %v", err)
	}
	defer l.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			time.Sleep(2 * time.Millisecond) // mock latency
			conn.Close()
		}
	}()

	manager := NewProxyCloudManager()

	// 1. Test app exclusions
	manager.SetExcludedPackages([]string{"com.android.chrome", "com.google.android.youtube"})
	if !manager.IsAppExcluded("com.android.chrome") {
		t.Errorf("expected Chrome to be excluded")
	}
	if !manager.IsAppExcluded("com.google.android.youtube") {
		t.Errorf("expected YouTube to be excluded")
	}
	if manager.IsAppExcluded("com.example.app") {
		t.Errorf("expected example app not to be excluded")
	}

	// 2. Test latency selection
	node1 := &ProxyCloudNode{
		ID:      "1",
		Remark:  "Local Mock Node",
		Address: l.Addr().String(),
	}
	node2 := &ProxyCloudNode{
		ID:      "2",
		Remark:  "Non-existent Node",
		Address: "127.0.0.1:54321", // will time out or refuse immediately
	}

	manager.ConfigureNodes([]*ProxyCloudNode{node1, node2})

	ctx := context.Background()
	fastest := manager.SelectFastestNode(ctx, 100*time.Millisecond)

	if fastest == nil {
		t.Fatalf("expected to find a fastest node, got nil")
	}
	if fastest.ID != "1" {
		t.Errorf("expected node 1 (local mock) to be fastest, got ID: %s", fastest.ID)
	}
}
