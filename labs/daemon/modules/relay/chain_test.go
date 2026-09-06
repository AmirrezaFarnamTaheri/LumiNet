package relay

import (
	"bytes"
	"testing"
)

func TestRelayChainEncryptDecrypt(t *testing.T) {
	key1 := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	key2 := [32]byte{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	rc, err := NewRelayChain([][32]byte{key1, key2})
	if err != nil {
		t.Fatalf("failed to create relay chain: %v", err)
	}

	payload := []byte("SECRET_LUMINET_MESH_PAYLOAD")

	encrypted, err := rc.Encrypt(payload)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Peel layer 1 (outermost hop: key1)
	layer1, err := DecryptLayer(key1, encrypted)
	if err != nil {
		t.Fatalf("decrypt layer 1 failed: %v", err)
	}

	// Peel layer 2 (innermost hop: key2)
	decrypted, err := DecryptLayer(key2, layer1)
	if err != nil {
		t.Fatalf("decrypt layer 2 failed: %v", err)
	}

	if !bytes.Equal(decrypted, payload) {
		t.Errorf("decrypted payload mismatch. Expected %s, got %s", payload, decrypted)
	}
}
