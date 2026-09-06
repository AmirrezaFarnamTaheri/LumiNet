package transport

import (
	"testing"
	"time"
)

func TestRendezvousBridgeFlow(t *testing.T) {
	bridge := NewRendezvousBridge(1 * time.Minute)

	token, err := bridge.RegisterPeer("10.0.0.1:5000")
	if err != nil {
		t.Fatalf("failed to register peer: %v", err)
	}

	sess, err := bridge.ConnectPeer(token, "10.0.0.2:6000")
	if err != nil {
		t.Fatalf("failed to connect peer: %v", err)
	}

	if !sess.IsConnected {
		t.Errorf("expected session to be connected")
	}
	if sess.Responder != "10.0.0.2:6000" {
		t.Errorf("unexpected responder addr: %s", sess.Responder)
	}
}

func TestRendezvousBridgeInvalidToken(t *testing.T) {
	bridge := NewRendezvousBridge(1 * time.Minute)
	_, err := bridge.ConnectPeer("nonexistent-token", "10.0.0.2:6000")
	if err == nil {
		t.Errorf("expected error on invalid token")
	}
}
