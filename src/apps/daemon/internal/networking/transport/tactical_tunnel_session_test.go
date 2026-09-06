package transport

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestTacticalStreamCipher(t *testing.T) {
	key := []byte("tactical_stream_test_key_123")
	enc := NewTacticalStreamCipher(key)
	dec := NewTacticalStreamCipher(key)

	original := []byte("The quick brown fox jumps over the lazy dog under tactical surveillance.")
	buf := append([]byte(nil), original...)

	enc.ApplyKeyStream(buf)
	if bytes.Equal(buf, original) {
		t.Fatal("expected ciphertext to differ from plaintext")
	}

	dec.ApplyKeyStream(buf)
	if !bytes.Equal(buf, original) {
		t.Fatalf("expected decrypted buffer to equal original, got: %s", string(buf))
	}
}

func TestDeriveTacticalKey(t *testing.T) {
	seed := make([]byte, ObfuscateSeedLength)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	keyword := []byte("luminet_tactical_keyword")

	k1, err := DeriveTacticalKey(seed, keyword, ObfuscateC2SIV)
	if err != nil {
		t.Fatalf("unexpected error deriving key: %v", err)
	}
	k2, err := DeriveTacticalKey(seed, keyword, ObfuscateC2SIV)
	if err != nil {
		t.Fatalf("unexpected error deriving key: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("expected deterministic key derivation")
	}

	k3, err := DeriveTacticalKey(seed, keyword, ObfuscateS2CIV)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bytes.Equal(k1, k3) {
		t.Fatal("expected distinct keys for c2s and s2c")
	}
}

func TestTacticalSessionObfuscatorRoundtrip(t *testing.T) {
	keyword := []byte("mission_critical_tactical_key")
	seed := make([]byte, ObfuscateSeedLength)
	for i := range seed {
		seed[i] = byte(0x30 + i)
	}
	padding := []byte("ANTI_FINGERPRINT_PADDING_DATA_BUFFER_XYZ")
	paddingLen := len(padding)

	client, err := NewClientTacticalObfuscator(keyword, seed, paddingLen)
	if err != nil {
		t.Fatalf("failed to create client obfuscator: %v", err)
	}

	preamble, err := client.GenerateClientPreamble(padding)
	if err != nil {
		t.Fatalf("failed to generate client preamble: %v", err)
	}
	if len(preamble) != PreambleHeaderLength+paddingLen {
		t.Fatalf("unexpected preamble len: %d, expected %d", len(preamble), PreambleHeaderLength+paddingLen)
	}

	server, recPadding, err := NewServerTacticalObfuscator(keyword, preamble)
	if err != nil {
		t.Fatalf("failed to create server obfuscator: %v", err)
	}
	if !bytes.Equal(recPadding, padding) {
		t.Fatalf("recovered padding mismatch: got %v, expected %v", recPadding, padding)
	}
	if server.Seed() != client.Seed() {
		t.Fatal("server and client seeds mismatch")
	}

	// Client to server stream
	reqMsg := []byte("CONNECT secure-edge.local:443 HTTP/1.1\r\n\r\n")
	reqBuf := append([]byte(nil), reqMsg...)
	client.ObfuscateClientToServer(reqBuf)
	if bytes.Equal(reqBuf, reqMsg) {
		t.Fatal("client to server payload not encrypted")
	}
	server.ObfuscateClientToServer(reqBuf)
	if !bytes.Equal(reqBuf, reqMsg) {
		t.Fatalf("decrypted client payload mismatch: %s", string(reqBuf))
	}

	// Server to client stream
	respMsg := []byte("HTTP/1.1 200 Connection Established\r\n\r\n")
	respBuf := append([]byte(nil), respMsg...)
	server.ObfuscateServerToClient(respBuf)
	if bytes.Equal(respBuf, respMsg) {
		t.Fatal("server to client payload not encrypted")
	}
	client.ObfuscateServerToClient(respBuf)
	if !bytes.Equal(respBuf, respMsg) {
		t.Fatalf("decrypted server payload mismatch: %s", string(respBuf))
	}
}

func TestTacticalSessionInvalidMagic(t *testing.T) {
	keyword := []byte("tactical_key")
	seed := make([]byte, ObfuscateSeedLength)
	client, err := NewClientTacticalObfuscator(keyword, seed, 8)
	if err != nil {
		t.Fatalf("client init err: %v", err)
	}

	preamble, err := client.GenerateClientPreamble([]byte("12345678"))
	if err != nil {
		t.Fatalf("preamble err: %v", err)
	}

	// Corrupt magic header
	preamble[16] ^= 0xEE

	_, _, err = NewServerTacticalObfuscator(keyword, preamble)
	if err == nil {
		t.Fatal("expected error on tampered preamble magic")
	}
}

func TestTacticalTunnelTransportHotSwap(t *testing.T) {
	clientConn, srvConn := net.Pipe()
	transport := NewTacticalTunnelTransport(srvConn)

	// Send message through pipe
	go func() {
		_, _ = clientConn.Write([]byte("PACKET_BATCH_1"))
	}()

	buf := make([]byte, 64)
	n, err := transport.Read(buf)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if string(buf[:n]) != "PACKET_BATCH_1" {
		t.Fatalf("expected PACKET_BATCH_1, got: %s", string(buf[:n]))
	}

	// Hot swap to a new connection
	newClientConn, newSrvConn := net.Pipe()
	transport.SwapChannel(newSrvConn)

	go func() {
		_, _ = newClientConn.Write([]byte("PACKET_BATCH_2_AFTER_HOTSWAP"))
	}()

	n, err = transport.Read(buf)
	if err != nil {
		t.Fatalf("read error after hotswap: %v", err)
	}
	if string(buf[:n]) != "PACKET_BATCH_2_AFTER_HOTSWAP" {
		t.Fatalf("expected PACKET_BATCH_2_AFTER_HOTSWAP, got: %s", string(buf[:n]))
	}

	_ = transport.Close()
	_ = clientConn.Close()
	_ = newClientConn.Close()
}

func TestServerExchangePayload(t *testing.T) {
	entry := &ServerExchangeEntry{
		ServerID:     "edge-frankfurt-01",
		Endpoints:    []string{"198.51.100.1:443", "198.51.100.2:8443"},
		Capabilities: []string{"FRONTED_HTTP", "OSSH_TUNNEL", "SHADOWSOCKS"},
		Signature:    "SIG_ED25519_VALIDATED_HASH_STRING",
		DialParameters: map[string]string{
			"tls_sni":    "cdn.target-gateway.org",
			"fronting":   "edge.cloudfront.net",
			"timeout_ms": "4500",
		},
		Timestamp: time.Now().Unix(),
	}

	exchangeKey := []byte("top_secret_exchange_obfuscation_key_32b")
	payload, err := ExportServerExchange(entry, exchangeKey)
	if err != nil {
		t.Fatalf("failed to export exchange payload: %v", err)
	}

	imported, err := ImportServerExchange(payload, exchangeKey)
	if err != nil {
		t.Fatalf("failed to import exchange payload: %v", err)
	}

	if imported.ServerID != entry.ServerID {
		t.Fatalf("server ID mismatch: got %s, expected %s", imported.ServerID, entry.ServerID)
	}
	if len(imported.Capabilities) != 3 {
		t.Fatalf("capabilities count mismatch: %d", len(imported.Capabilities))
	}
	if imported.DialParameters["fronting"] != "edge.cloudfront.net" {
		t.Fatalf("dial parameter mismatch: %s", imported.DialParameters["fronting"])
	}

	// Test tampering detection
	payload[20] ^= 0xFF
	_, err = ImportServerExchange(payload, exchangeKey)
	if err == nil {
		t.Fatal("expected error when importing tampered payload")
	}
}

func TestTacticalEngine(t *testing.T) {
	defaultProfile := NewTacticalProfile(time.Hour, map[string]string{
		"timeout_ms": "5000",
		"pool_size":  "2",
	})
	engine := NewTacticalEngine(defaultProfile)

	engine.AddFilter(&TacticalFilter{
		Regions: []string{"IR", "CN"},
		ASNs:    []uint32{44212},
		Profile: NewTacticalProfile(30*time.Minute, map[string]string{
			"timeout_ms":        "12000",
			"pool_size":         "6",
			"tunnel_protocols":  "FRONTED_HTTP,SSH_OBFUSCATED",
		}),
	})

	// Non-matching
	p1 := engine.ResolveProfile("DE", 3320, 30, true)
	if p1.Parameters["timeout_ms"] != "5000" {
		t.Fatalf("expected default timeout 5000, got: %s", p1.Parameters["timeout_ms"])
	}
	if _, ok := p1.Parameters["tunnel_protocols"]; ok {
		t.Fatal("unexpected tunnel_protocols in non-matching profile")
	}

	// Matching
	p2 := engine.ResolveProfile("IR", 44212, 180, true)
	if p2.Parameters["timeout_ms"] != "12000" {
		t.Fatalf("expected filtered timeout 12000, got: %s", p2.Parameters["timeout_ms"])
	}
	if p2.Parameters["pool_size"] != "6" {
		t.Fatalf("expected pool_size 6, got: %s", p2.Parameters["pool_size"])
	}
	if p2.Parameters["tunnel_protocols"] != "FRONTED_HTTP,SSH_OBFUSCATED" {
		t.Fatalf("unexpected tunnel_protocols: %s", p2.Parameters["tunnel_protocols"])
	}
	if p1.Tag == p2.Tag {
		t.Fatal("expected different tags for different profiles")
	}
}
