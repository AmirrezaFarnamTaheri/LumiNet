package safety

import (
	"testing"
)

func TestPeerAclEvaluator(t *testing.T) {
	eval := NewPeerAclEvaluator(true)
	eval.SetRule("peer1", "peer2", false)

	if eval.IsAllowed("peer1", "peer2") {
		t.Fatal("peer1 -> peer2 should be blocked")
	}
	if !eval.IsAllowed("peer1", "peer3") {
		t.Fatal("peer1 -> peer3 should follow default allow")
	}

	evalDefaultBlock := NewPeerAclEvaluator(false)
	evalDefaultBlock.SetRule("admin", "db", true)
	if !evalDefaultBlock.IsAllowed("admin", "db") {
		t.Fatal("admin -> db should be allowed")
	}
	if evalDefaultBlock.IsAllowed("guest", "db") {
		t.Fatal("guest -> db should be blocked by default")
	}
}
