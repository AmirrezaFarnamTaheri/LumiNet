package security

import (
	"encoding/json"
	"testing"
)

func TestEncryptDecryptPayload(t *testing.T) {
	passphrase := "whitevpn-daemon-secret-key"
	message := "https://relay.whitevpn.internal/catalog/nodes.json"

	encryptedJSON, err := EncryptPayload([]byte(message), passphrase)
	if err != nil {
		t.Fatalf("EncryptPayload failed: %v", err)
	}

	var env EncryptedPayloadEnvelope
	if err := json.Unmarshal([]byte(encryptedJSON), &env); err != nil {
		t.Fatalf("invalid json envelope: %v", err)
	}
	if env.Version != 1 || env.Algorithm != "AES-GCM" || env.Encoding != "base64url" {
		t.Fatalf("unexpected envelope headers: %+v", env)
	}

	decrypted, err := DecryptText(encryptedJSON, passphrase)
	if err != nil {
		t.Fatalf("DecryptText failed: %v", err)
	}
	if decrypted != message {
		t.Fatalf("expected '%s', got '%s'", message, decrypted)
	}
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	encryptedJSON, err := EncryptPayload([]byte("hello secret"), "key-one")
	if err != nil {
		t.Fatalf("EncryptPayload failed: %v", err)
	}

	_, err = DecryptText(encryptedJSON, "key-two")
	if err == nil {
		t.Fatalf("expected decryption error with wrong key")
	}
}

func TestParseAndEncryptIPList(t *testing.T) {
	rawText := "192.0.2.1  198.51.100.1\n\n192.0.2.1  bad.ip 256.0.0.1 1.1.1.1"
	ips := ParsePlaintextIPs(rawText)
	if len(ips) != 3 {
		t.Fatalf("expected 3 distinct valid IPs, got %d: %v", len(ips), ips)
	}

	passphrase := "ip-list-passphrase"
	encrypted, err := EncryptIPList(ips, passphrase)
	if err != nil {
		t.Fatalf("EncryptIPList failed: %v", err)
	}

	decryptedIPs, err := DecryptIPList(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptIPList failed: %v", err)
	}
	if len(decryptedIPs) != 3 || decryptedIPs[0] != "192.0.2.1" {
		t.Fatalf("unexpected decrypted IPs: %v", decryptedIPs)
	}
}
