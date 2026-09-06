package proxy

import (
	"encoding/binary"
	"testing"
)

func TestUserspaceStack_DeliverIPPacket(t *testing.T) {
	stack := NewUserspaceStack("10.0.0.1", 1500)

	// Construct a dummy IPv4 TCP packet
	packet := make([]byte, 40)
	packet[0] = 0x45 // Version 4, Header length 20 bytes (5 * 4)
	packet[9] = 6    // TCP protocol
	// Source IP: 10.0.0.2
	packet[12], packet[13], packet[14], packet[15] = 10, 0, 0, 2
	// Destination IP: 10.0.0.1
	packet[16], packet[17], packet[18], packet[19] = 10, 0, 0, 1

	// TCP ports
	binary.BigEndian.PutUint16(packet[20:22], 12345) // Src Port
	binary.BigEndian.PutUint16(packet[22:24], 80)    // Dst Port

	err := stack.DeliverIPPacket(packet)
	if err != nil {
		t.Fatalf("failed to deliver valid packet: %v", err)
	}

	// Test with short packet
	err = stack.DeliverIPPacket(make([]byte, 10))
	if err == nil {
		t.Errorf("expected error for short packet, got nil")
	}

	// Test with wrong version
	packet[0] = 0x55 // Version 5
	err = stack.DeliverIPPacket(packet)
	if err == nil {
		t.Errorf("expected error for wrong version, got nil")
	}
}
