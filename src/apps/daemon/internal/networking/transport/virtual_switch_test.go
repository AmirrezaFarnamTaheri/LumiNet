package transport

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestVirtualEthernetSwitchFdb(t *testing.T) {
	sw := NewVirtualEthernetSwitch(50 * time.Millisecond)
	src := NodeAddress{0x10, 0x20, 0x30, 0x40, 0x50}
	dst := NodeAddress{0xaa, 0xbb, 0xcc, 0xdd, 0xee}

	udpAddr, _ := net.ResolveUDPAddr("udp", "198.51.100.1:9993")
	sw.Learn(src, udpAddr)

	found, ok := sw.Lookup(src)
	if !ok || found.String() != udpAddr.String() {
		t.Fatalf("lookup failed for learned node")
	}

	frame := &SwitchPacketFrame{
		Source:      src,
		Destination: dst,
		EtherType:   0x0800,
		Payload:     []byte("test-ip-payload"),
	}
	encoded := frame.Encode()
	decoded, err := DecodeSwitchPacketFrame(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if decoded.Source != src || decoded.Destination != dst || !bytes.Equal(decoded.Payload, frame.Payload) {
		t.Fatal("decoded frame does not match")
	}
}
