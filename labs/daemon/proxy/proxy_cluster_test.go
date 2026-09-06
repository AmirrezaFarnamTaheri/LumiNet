// Package proxy provides proxy test specifications.
// Target path: server/internal/proxy/proxy_cluster_test.go

package proxy

import (
	"testing"
)

func TestProxyClusterManager_AllocateCluster(t *testing.T) {
	mgr := NewProxyClusterManager("127.0.0.1", 20000)

	nodes := []ProxyClusterNode{
		{Name: "ss-node-01", Type: "shadowsocks"},
		{Name: "vless-node-01", Type: "vless"},
	}

	inbounds, rules, err := mgr.AllocateCluster(nodes)
	if err != nil {
		t.Fatalf("AllocateCluster failed: %v", err)
	}

	if len(inbounds) != 2 || len(rules) != 2 {
		t.Errorf("Expected 2 inbounds and 2 rules, got %d and %d", len(inbounds), len(rules))
	}

	// Verify ports are allocated sequentially
	p1 := inbounds[0].ListenPort
	p2 := inbounds[1].ListenPort
	if p1 != 20000 || p2 != 20001 {
		t.Errorf("Expected port 20000 and 20001, got %d and %d", p1, p2)
	}

	// Check tagPort mapping persistence
	p1Cached := mgr.TagPorts["ss-node-01"]
	if p1Cached != p1 {
		t.Errorf("Cache mismatch: %d vs %d", p1Cached, p1)
	}
}
