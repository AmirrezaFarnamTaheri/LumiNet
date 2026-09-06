// Package proxy provides packet tunneling test specifications.
// Target path: server/internal/proxy/fptn_codec_test.go

package proxy

import (
	"bytes"
	"testing"
)

func TestFPTNPacketCodec_Roundtrip_IPAssignment(t *testing.T) {
	codec := NewFPTNPacketCodec()

	msg := &FPTNMessage{
		Version:     2,
		Type:        FPTNMsgIPAssignment,
		IPv4Address: "10.0.0.2",
		IPv6Address: "fc00::2",
	}

	encoded := codec.Encode(msg)
	decoded, err := codec.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.Version != msg.Version {
		t.Errorf("Expected version %d, got %d", msg.Version, decoded.Version)
	}
	if decoded.Type != msg.Type {
		t.Errorf("Expected type %d, got %d", msg.Type, decoded.Type)
	}
	if decoded.IPv4Address != msg.IPv4Address {
		t.Errorf("Expected IPv4Address %q, got %q", msg.IPv4Address, decoded.IPv4Address)
	}
	if decoded.IPv6Address != msg.IPv6Address {
		t.Errorf("Expected IPv6Address %q, got %q", msg.IPv6Address, decoded.IPv6Address)
	}
}

func TestFPTNPacketCodec_Roundtrip_BatchPacket(t *testing.T) {
	codec := NewFPTNPacketCodec()

	msg := &FPTNMessage{
		Version: 1,
		Type:    FPTNMsgBatchPacket,
		BatchPackets: [][]byte{
			{0x45, 0x00, 0x00, 0x28, 0x01, 0x02, 0x00, 0x00, 0x40, 0x06, 0x3d, 0xbc, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02},
			{0x45, 0x00, 0x00, 0x28, 0x02, 0x03, 0x00, 0x00, 0x40, 0x06, 0x3d, 0xba, 0x0a, 0x00, 0x00, 0x02, 0x0a, 0x00, 0x00, 0x01},
		},
	}

	encoded := codec.Encode(msg)
	decoded, err := codec.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.Type != msg.Type {
		t.Errorf("Expected type %d, got %d", msg.Type, decoded.Type)
	}
	if len(decoded.BatchPackets) != len(msg.BatchPackets) {
		t.Fatalf("Expected %d packets, got %d", len(msg.BatchPackets), len(decoded.BatchPackets))
	}
	for i, pkt := range msg.BatchPackets {
		if !bytes.Equal(decoded.BatchPackets[i], pkt) {
			t.Errorf("Packet %d mismatch: expected %x, got %x", i, pkt, decoded.BatchPackets[i])
		}
	}
}
