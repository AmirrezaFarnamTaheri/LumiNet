// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package transport

import (
	"bytes"
	"testing"
)

func TestDecoyEnvelope_AES256CBC_Roundtrip(t *testing.T) {
	envelope := DecoyEnvelope{}
	key := bytes.Repeat([]byte{0x42}, 32)
	message := []byte("GET /api/v1/telemetry HTTP/1.1\r\nHost: target.internal\r\n\r\n")

	encrypted, err := envelope.Encrypt(message, key)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	if len(encrypted) < 32 {
		t.Fatalf("expected encrypted output >= 32 bytes, got %d", len(encrypted))
	}

	decrypted, err := envelope.Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted, message) {
		t.Fatalf("decrypted payload mismatch: expected %q, got %q", message, decrypted)
	}
}

func TestDecoyAgent_Server_Roundtrip(t *testing.T) {
	config := DefaultDecoyTunnelConfig()
	agent := NewDecoyAgent(config)
	server := NewDecoyServer(config)

	sessionID := "agent-sess-uuid-98765"
	originalPayload := []byte("CONNECT secure.target.net:443 HTTP/1.1\r\nHost: secure.target.net\r\n\r\n")

	// 1. Agent encodes request
	wireReq, err := agent.EncodeRequest(sessionID, ActionOpen, originalPayload, 0)
	if err != nil {
		t.Fatalf("agent encode request failed: %v", err)
	}

	// 2. Server decodes request
	req, innerPayload, err := server.DecodeRequest(wireReq)
	if err != nil {
		t.Fatalf("server decode request failed: %v", err)
	}

	if req.SessionID != sessionID {
		t.Fatalf("expected session ID %q, got %q", sessionID, req.SessionID)
	}
	if req.Action != ActionOpen {
		t.Fatalf("expected action %q, got %q", ActionOpen, req.Action)
	}
	if !bytes.Equal(innerPayload, originalPayload) {
		t.Fatalf("payload mismatch: expected %q, got %q", originalPayload, innerPayload)
	}

	// 3. Server encodes response
	respPayload := []byte("HTTP/1.1 200 Connection Established\r\nProxy-Agent: LumiNet\r\n\r\n")
	wireResp, err := server.EncodeResponse(200, "Connection Established", respPayload, true)
	if err != nil {
		t.Fatalf("server encode response failed: %v", err)
	}

	// 4. Agent decodes response
	resp, decryptedResp, err := agent.DecodeResponse(wireResp)
	if err != nil {
		t.Fatalf("agent decode response failed: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Fatalf("expected status code 200, got %d", resp.StatusCode)
	}
	if !resp.KeepAlive {
		t.Fatalf("expected keep-alive response")
	}
	if !bytes.Equal(decryptedResp, respPayload) {
		t.Fatalf("decrypted response mismatch: expected %q, got %q", respPayload, decryptedResp)
	}
}

func TestDecoyAction_Parsing(t *testing.T) {
	actions := map[string]DecoyAction{
		"open":    ActionOpen,
		"request": ActionRequest,
		"send":    ActionSend,
		"recv":    ActionRecv,
		"close":   ActionClose,
	}

	for str, expected := range actions {
		act, err := ParseDecoyAction(str)
		if err != nil {
			t.Fatalf("unexpected error parsing %q: %v", str, err)
		}
		if act != expected {
			t.Fatalf("expected %v, got %v", expected, act)
		}
	}

	// Test custom
	custom, err := ParseDecoyAction("custom_tunnel_step")
	if err != nil {
		t.Fatalf("failed to parse custom action: %v", err)
	}
	if custom != DecoyAction("custom_tunnel_step") {
		t.Fatalf("expected custom action, got %v", custom)
	}

	// Test empty
	_, err = ParseDecoyAction("")
	if err == nil {
		t.Fatalf("expected error on empty action")
	}
}

func TestDecoyTunnelConfig_DeriveKey(t *testing.T) {
	cfg1 := &DecoyTunnelConfig{Token: "12345678901234567890123456789012"} // exactly 32 bytes
	key1 := cfg1.DeriveKey()
	if string(key1[:]) != cfg1.Token {
		t.Fatalf("expected direct 32-byte key match")
	}

	cfg2 := &DecoyTunnelConfig{Token: "short-token"}
	key2 := cfg2.DeriveKey()
	if len(key2) != 32 {
		t.Fatalf("derived key length is not 32 bytes")
	}
}

func TestDecoySession_Lifecycle(t *testing.T) {
	sess := NewDecoySession("sess-42")
	if sess.IsConnected {
		t.Fatalf("new session should not be connected")
	}

	sess.MarkConnected()
	if !sess.IsConnected {
		t.Fatalf("session should be marked connected")
	}
	if sess.ActiveAction != ActionSend {
		t.Fatalf("expected active action Send, got %v", sess.ActiveAction)
	}

	sess.RecordSent(512)
	sess.RecordReceived(1024)
	if sess.BytesSent != 512 || sess.BytesReceived != 1024 {
		t.Fatalf("byte counters mismatch: sent %d, recv %d", sess.BytesSent, sess.BytesReceived)
	}

	sess.MarkClosed()
	if sess.IsConnected {
		t.Fatalf("session should be marked closed")
	}
	if sess.ActiveAction != ActionClose {
		t.Fatalf("expected active action Close, got %v", sess.ActiveAction)
	}
}

func TestDecoyServer_InvalidInput(t *testing.T) {
	config := DefaultDecoyTunnelConfig()
	server := NewDecoyServer(config)

	// Missing header terminator
	_, _, err := server.DecodeRequest([]byte("GET / HTTP/1.1\r\nHost: example.com"))
	if err == nil {
		t.Fatalf("expected error on incomplete request")
	}

	// Missing X-Nipo-Action header
	badReq := "GET / HTTP/1.1\r\nHost: example.com\r\nX-Nipo-Session: 123\r\n\r\n"
	_, _, err = server.DecodeRequest([]byte(badReq))
	if err == nil {
		t.Fatalf("expected error on missing action header")
	}
}
