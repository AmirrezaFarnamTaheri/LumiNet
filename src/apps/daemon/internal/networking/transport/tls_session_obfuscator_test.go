package transport

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestPadAndUnpadSessionTicket(t *testing.T) {
	rawTicket := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	padded := PadSessionTicket(rawTicket)

	if len(padded) != 160 {
		t.Fatalf("expected 160 bytes padding, got %d", len(padded))
	}
	if !bytes.Equal(padded[:5], rawTicket) {
		t.Fatalf("prefix mismatch")
	}

	unpadded := UnpadSessionTicket(padded)
	if !bytes.Equal(unpadded, rawTicket) {
		t.Fatalf("unpad mismatch: got %v want %v", unpadded, rawTicket)
	}

	// 170 bytes -> 176 bytes
	raw170 := bytes.Repeat([]byte{0x11}, 170)
	padded176 := PadSessionTicket(raw170)
	if len(padded176) != 176 {
		t.Fatalf("expected 176 bytes padding, got %d", len(padded176))
	}
	if !bytes.Equal(UnpadSessionTicket(padded176), raw170) {
		t.Fatalf("unpad 176 mismatch")
	}
}

func TestObfuscatedClientSessionStateRoundtrip(t *testing.T) {
	ticket := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	secret := bytes.Repeat([]byte{0x42}, 32)
	state := NewObfuscatedClientSessionState(
		ticket,
		0x0304,
		0x1301,
		secret,
		1710000000,
		12345,
		1710100000,
	)

	if len(state.Ticket) != 160 {
		t.Fatalf("expected padded ticket length 160, got %d", len(state.Ticket))
	}

	serialized := state.Serialize()
	deserialized, err := DeserializeObfuscatedClientSessionState(serialized)
	if err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}

	if deserialized.Vers != 0x0304 || deserialized.CipherSuite != 0x1301 || deserialized.CreatedAt != 1710000000 {
		t.Fatalf("field mismatch in deserialized state: %+v", deserialized)
	}
	if !bytes.Equal(deserialized.MasterSecret, secret) {
		t.Fatalf("master secret mismatch")
	}
	if !bytes.Equal(UnpadSessionTicket(deserialized.Ticket), ticket) {
		t.Fatalf("ticket mismatch")
	}
}

func TestTLSPassthroughDeflector(t *testing.T) {
	deflector := NewTLSPassthroughDeflector(
		"192.0.2.1:443",
		[]string{"secret-auth-token-123"},
	)

	// Valid token
	if deflector.ShouldDeflect("secret-auth-token-123") {
		t.Fatalf("expected ShouldDeflect=false for valid token")
	}

	// Invalid token
	if !deflector.ShouldDeflect("wrong-token") {
		t.Fatalf("expected ShouldDeflect=true for invalid token")
	}

	// Empty token
	if !deflector.ShouldDeflect("") {
		t.Fatalf("expected ShouldDeflect=true for empty token")
	}

	// Disabled deflector
	disabled := NewTLSPassthroughDeflector("", nil)
	if disabled.ShouldDeflect("") {
		t.Fatalf("expected ShouldDeflect=false when passthrough disabled")
	}
}

func TestParseECHConfigList(t *testing.T) {
	var configBody []byte
	configBody = append(configBody, 0x01) // config_id = 1
	configBody = binary.BigEndian.AppendUint16(configBody, 0x0020) // kem_id
	configBody = binary.BigEndian.AppendUint16(configBody, 4) // pk len
	configBody = append(configBody, 0x10, 0x20, 0x30, 0x40) // pk

	// Cipher suites
	configBody = binary.BigEndian.AppendUint16(configBody, 4) // cipher len
	configBody = binary.BigEndian.AppendUint16(configBody, 0x0001) // kdf
	configBody = binary.BigEndian.AppendUint16(configBody, 0x0001) // aead

	configBody = append(configBody, 64) // max name len
	pubName := []byte("cloudflare-ech.com")
	configBody = append(configBody, byte(len(pubName)))
	configBody = append(configBody, pubName...)

	var configEntry []byte
	configEntry = binary.BigEndian.AppendUint16(configEntry, 0xfe0d) // version
	configEntry = binary.BigEndian.AppendUint16(configEntry, uint16(len(configBody)))
	configEntry = append(configEntry, configBody...)

	var data []byte
	data = binary.BigEndian.AppendUint16(data, uint16(len(configEntry)))
	data = append(data, configEntry...)

	configs, err := ParseECHConfigList(data)
	if err != nil {
		t.Fatalf("ParseECHConfigList failed: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("expected 1 config, got %d", len(configs))
	}
	c := configs[0]
	if c.Version != 0xfe0d || c.ConfigID != 1 || c.KemID != 0x0020 || c.PublicName != "cloudflare-ech.com" {
		t.Fatalf("unexpected config: %+v", c)
	}
	if len(c.CipherSuites) != 1 || c.CipherSuites[0].KDFID != 1 || c.CipherSuites[0].AEADID != 1 {
		t.Fatalf("unexpected cipher suites: %+v", c.CipherSuites)
	}
}
