package transport

import (
	"net"
	"testing"
)

func TestMultipathEvasionPipeline(t *testing.T) {
	pipe := NewMultipathEvasionPipeline("pipe-01", BondingLowestLatency, 2, 0xCAFE, RegionIran)

	local := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 7001}
	remote := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 9000}
	pipe.RegisterPath(1, local, remote, 10)

	dest := &net.TCPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443}
	payload := make([]byte, 40)
	payload[0] = 0x45

	pathID, frame, err := pipe.PrepareOutboundPacket(dest, payload)
	if err != nil {
		t.Fatal(err)
	}
	if pathID != 1 || len(frame) <= len(payload) {
		t.Fatalf("unexpected frame: path=%d len=%d", pathID, len(frame))
	}
}
