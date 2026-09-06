package proxyconfig

import (
	"net"
	"testing"
)

func TestMeshSocks5Bridge(t *testing.T) {
	bridge := NewMeshSocks5Bridge(1080)

	// Test No Auth greeting
	greeting := []byte{0x05, 0x01, 0x00}
	method, err := bridge.ParseGreeting(greeting)
	if err != nil || method != 0x00 {
		t.Fatalf("expected 0x00 no auth, got %02x, err: %v", method, err)
	}

	// Add User
	bridge.AddUser("alice", "hunter2")
	_, err = bridge.ParseGreeting(greeting)
	if err == nil {
		t.Fatalf("expected failure when credentials required")
	}

	greetingAuth := []byte{0x05, 0x02, 0x00, 0x02}
	methodAuth, err := bridge.ParseGreeting(greetingAuth)
	if err != nil || methodAuth != 0x02 {
		t.Fatalf("expected 0x02 user/pass auth, got %02x", methodAuth)
	}

	if !bridge.Authenticate("alice", "hunter2") {
		t.Fatalf("expected authentication success")
	}
	if bridge.Authenticate("alice", "wrong") {
		t.Fatalf("expected authentication failure")
	}

	// Route evaluation
	exitIP := net.ParseIP("100.64.0.50")
	bridge.SetExitTarget(&MeshExitTarget{
		NodeID:    "exit-node-1",
		VirtualIP: exitIP,
		Active:    true,
	})

	decisionLocal, _ := bridge.EvaluateRoute("localhost", 80)
	if decisionLocal != Socks5RouteDirect {
		t.Fatalf("expected direct route for localhost")
	}

	decisionMesh, ip := bridge.EvaluateRoute("example.com", 443)
	if decisionMesh != Socks5RouteMeshExit || !ip.Equal(exitIP) {
		t.Fatalf("expected mesh exit route with %v, got %v / %v", exitIP, decisionMesh, ip)
	}

	// Craft reply
	reply := bridge.CraftReply(0x00, net.ParseIP("127.0.0.1"), 1080)
	if len(reply) != 10 || reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("invalid crafted reply: %v", reply)
	}
}
