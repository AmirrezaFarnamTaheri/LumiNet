package security

import (
	"encoding/binary"
	"testing"
)

func TestIpsecIkev2StateMachine(t *testing.T) {
	secret := []byte("ikev2-strong-pre-shared-key-1234")
	sm, err := NewIpsecIkev2StateMachine(secret)
	if err != nil {
		t.Fatalf("failed to create IKEv2 state machine: %v", err)
	}

	if sm.State() != IkeStateInit {
		t.Fatalf("expected initial state INIT, got %s", sm.State())
	}

	nonce := []byte("random-initiator-nonce-32-bytes")
	req, err := sm.BuildSaInitRequest(nonce)
	if err != nil {
		t.Fatalf("failed to build SA_INIT request: %v", err)
	}
	if len(req) < 28 {
		t.Fatalf("expected req len >= 28, got %d", len(req))
	}
	if sm.State() != IkeStateSaInitSent {
		t.Fatalf("expected state SA_INIT_SENT, got %s", sm.State())
	}

	// Mock responder packet
	resp := make([]byte, 28)
	binary.BigEndian.PutUint64(resp[0:8], sm.InitiatorSPI())
	binary.BigEndian.PutUint64(resp[8:16], 9876543210) // responder SPI
	resp[18] = byte(ExchangeIkeSaInit)

	if err := sm.ProcessSaInitResponse(resp); err != nil {
		t.Fatalf("process SA_INIT response failed: %v", err)
	}
	if sm.State() != IkeStateSaInitRecv {
		t.Fatalf("expected state SA_INIT_RECV, got %s", sm.State())
	}

	if err := sm.TransitionToAuthSent(); err != nil {
		t.Fatalf("transition to auth failed: %v", err)
	}
	if sm.State() != IkeStateAuthSent {
		t.Fatalf("expected AUTH_SENT")
	}

	if err := sm.FinalizeEstablished(); err != nil {
		t.Fatalf("finalize established failed: %v", err)
	}
	if sm.State() != IkeStateEstablished {
		t.Fatalf("expected ESTABLISHED")
	}

	sm.Close()
	if sm.State() != IkeStateClosed {
		t.Fatalf("expected CLOSED")
	}
}
