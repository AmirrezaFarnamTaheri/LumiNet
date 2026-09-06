package transport

import (
	"net"
	"testing"
	"time"
)

func TestPacketScrambler(t *testing.T) {
	scrambler := NewPacketScrambler(2, 0xCAFE)
	dest := &net.TCPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443}

	packet := make([]byte, 40)
	packet[0] = 0x45 // IPv4 20 bytes
	packet[8] = 128  // Original TTL
	packet[9] = 6    // TCP
	packet[20+13] = 0x12 // SYN+ACK

	act := scrambler.ProcessIPPacket(dest, packet)
	if act != ActionAlterTTL || packet[8] != 64 {
		t.Fatalf("expected AlterTTL with 64, got %v, ttl=%d", act, packet[8])
	}

	scrambler.AddShortcut(dest.String(), time.Minute)
	act2 := scrambler.ProcessIPPacket(dest, packet)
	if act2 != ActionMarkPacket {
		t.Fatalf("expected MarkPacket on shortcut, got %v", act2)
	}
}
