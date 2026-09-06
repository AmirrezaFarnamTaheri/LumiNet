package transport

import (
	"testing"
)

func TestMultiprotocolTrafficInspector(t *testing.T) {
	policy := InspectorPolicy{
		AllowRDP:   true,
		AllowSSH:   true,
		AllowTLS:   true,
		AllowHTTP:  false, // Deny HTTP
		EnforceSNI: false,
	}
	inspector := NewMultiprotocolTrafficInspector(policy)

	// Test SSH inspection
	sshData := []byte("SSH-2.0-OpenSSH_8.9p1\r\n")
	proto, verdict, banner := inspector.Inspect(sshData)
	if proto != InspectedProtoSSH || verdict != VerdictPermitted || banner != "SSH-2.0-OpenSSH_8.9p1" {
		t.Fatalf("unexpected SSH result: %v %v %s", proto, verdict, banner)
	}

	// Test RDP inspection
	rdpData := []byte{0x03, 0x00, 0x00, 0x13}
	protoRDP, verdictRDP, _ := inspector.Inspect(rdpData)
	if protoRDP != InspectedProtoRDP || verdictRDP != VerdictPermitted {
		t.Fatalf("unexpected RDP result: %v %v", protoRDP, verdictRDP)
	}

	// Test HTTP denial policy
	httpData := []byte("GET / HTTP/1.1\r\nHost: test.com\r\n\r\n")
	protoHTTP, verdictHTTP, _ := inspector.Inspect(httpData)
	if protoHTTP != InspectedProtoHTTP || verdictHTTP != VerdictDenied {
		t.Fatalf("expected HTTP denied by policy, got: %v %v", protoHTTP, verdictHTTP)
	}

	// Test WebSocket
	policy.AllowHTTP = true
	inspectorWS := NewMultiprotocolTrafficInspector(policy)
	wsData := []byte("GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	protoWS, verdictWS, _ := inspectorWS.Inspect(wsData)
	if protoWS != InspectedProtoWebSocket || verdictWS != VerdictPermitted {
		t.Fatalf("expected WebSocket permitted, got: %v %v", protoWS, verdictWS)
	}
}
