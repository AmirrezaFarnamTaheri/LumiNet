package transport

import (
	"bytes"
	"testing"
)

func TestReplayResistantTunnelSession(t *testing.T) {
	cfg := DefaultReplayResistantConfig()
	cRand := []byte("c_rand_123456789")
	sRand := []byte("s_rand_987654321")

	sender := NewReplayResistantTunnelSession(cfg, cRand, sRand)
	receiver := NewReplayResistantTunnelSession(cfg, cRand, sRand)

	now := int64(1700000000)
	payload := []byte("confidential packet contents")
	sealed := sender.SealPacket(1, now, payload)

	seq, ts, decrypted, err := receiver.OpenPacket(sealed, now+2)
	if err != nil {
		t.Fatalf("open packet failed: %v", err)
	}

	if seq != 1 || ts != now {
		t.Errorf("sequence or timestamp mismatch: seq=%d, ts=%d", seq, ts)
	}
	if !bytes.Equal(decrypted, payload) {
		t.Errorf("payload mismatch")
	}

	// Replay should fail
	_, _, _, err = receiver.OpenPacket(sealed, now+3)
	if err == nil {
		t.Errorf("expected error on replayed packet")
	}
}
