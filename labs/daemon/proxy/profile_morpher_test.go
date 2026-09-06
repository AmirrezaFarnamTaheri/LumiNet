package proxy

import (
	"bytes"
	"testing"
)

func TestProfileMorpher(t *testing.T) {
	pm := NewProfileMorpher("yandex")
	if pm.Profile.Name != "Yandex Video" {
		t.Errorf("expected Yandex Video profile, got %s", pm.Profile.Name)
	}

	// Verify ChooseTargetSize
	size := pm.ChooseTargetSize()
	found := false
	for _, s := range pm.Profile.PacketSizes {
		if size == s {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("unexpected target size %d", size)
	}

	// Test Morphing & Restoring small payload
	payload := []byte("secret payload details")
	morphed := pm.Morph(payload)

	if len(morphed) < len(payload)+4 {
		t.Errorf("morphed packet too short: %d", len(morphed))
	}

	restored, err := pm.Restore(morphed)
	if err != nil {
		t.Fatalf("failed to restore packet: %v", err)
	}

	if !bytes.Equal(payload, restored) {
		t.Errorf("mismatch: expected %s, got %s", string(payload), string(restored))
	}

	// Test Morphing & Restoring large payload (larger than target size)
	largePayload := make([]byte, 2000)
	for i := range largePayload {
		largePayload[i] = byte(i % 256)
	}

	morphedLarge := pm.Morph(largePayload)
	restoredLarge, err := pm.Restore(morphedLarge)
	if err != nil {
		t.Fatalf("failed to restore large packet: %v", err)
	}

	if !bytes.Equal(largePayload, restoredLarge) {
		t.Error("restored large payload differs from original")
	}
}
