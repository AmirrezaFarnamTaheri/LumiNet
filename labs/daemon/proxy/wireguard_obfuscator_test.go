package proxy

import (
	"bytes"
	"testing"
)

func TestWireGuardObfuscator_IndexMapping(t *testing.T) {
	obfs := NewWireGuardObfuscator("test-key")

	obfs.MapIndex(100, 200)
	backend, ok := obfs.GetBackendIndex(100)
	if !ok || backend != 200 {
		t.Errorf("expected backend index 200, got %d (ok=%t)", backend, ok)
	}

	client, ok := obfs.GetClientIndex(200)
	if !ok || client != 100 {
		t.Errorf("expected client index 100, got %d (ok=%t)", client, ok)
	}

	_, ok = obfs.GetBackendIndex(999)
	if ok {
		t.Error("expected ok=false for non-existent mapping")
	}
}

func TestWireGuardObfuscator_InitiationObfuscation(t *testing.T) {
	obfs := NewWireGuardObfuscator("user-key")

	// Construct mock MessageInitiation packet
	origPayload := make([]byte, 1024)
	origPayload[0] = MessageInitiationType // message type
	origPayload[4] = 10                    // sender index
	origPayload[8] = 20                    // receiver index

	pkt := &WgPacket{
		Data:   append([]byte(nil), origPayload...),
		Length: MessageInitiationSize,
		Flags:  PacketFlagObfuscateBeforeSend,
	}

	obfs.Obfuscate(pkt)

	if pkt.Length <= MessageInitiationSize {
		t.Errorf("expected padded packet length to be greater than initiation size, got %d", pkt.Length)
	}

	if bytes.Equal(pkt.Data[:16], origPayload[:16]) {
		t.Error("expected payload header to be obfuscated (changed)")
	}

	// Deobfuscate
	obfs.Deobfuscate(pkt)

	if pkt.Length != MessageInitiationSize {
		t.Errorf("expected deobfuscated length %d, got %d", MessageInitiationSize, pkt.Length)
	}

	if pkt.Data[0] != MessageInitiationType {
		t.Errorf("expected deobfuscated message type %d, got %d", MessageInitiationType, pkt.Data[0])
	}
}

func TestWireGuardObfuscator_TransportObfuscation(t *testing.T) {
	obfs := NewWireGuardObfuscator("another-key")

	origPayload := make([]byte, 500)
	origPayload[0] = MessageTransportType
	origPayload[4] = 99 // receiver index

	pkt := &WgPacket{
		Data:   append([]byte(nil), origPayload...),
		Length: 100, // shorter than kObfuscateSuffixAsNonceMinLength (256)
		Flags:  PacketFlagObfuscateBeforeSend,
	}

	obfs.Obfuscate(pkt)

	if pkt.Length != 100+kObfuscateNonceLength {
		t.Errorf("expected padded length %d, got %d", 100+kObfuscateNonceLength, pkt.Length)
	}

	obfs.Deobfuscate(pkt)

	if pkt.Length != 100 {
		t.Errorf("expected deobfuscated length 100, got %d", pkt.Length)
	}

	if pkt.Data[0] != MessageTransportType {
		t.Errorf("expected deobfuscated message type %d, got %d", MessageTransportType, pkt.Data[0])
	}
}
