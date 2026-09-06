package transport

import (
	"bytes"
	"net"
	"testing"
)

func TestRawTCPFlags(t *testing.T) {
	flags, err := ParseRawTCPFlags("PA")
	if err != nil {
		t.Fatalf("ParseRawTCPFlags failed: %v", err)
	}
	if !flags.PSH || !flags.ACK || flags.SYN {
		t.Fatalf("unexpected flags state: %+v", flags)
	}
	if flags.String() != "PA" {
		t.Fatalf("unexpected string: %s", flags.String())
	}

	encoded := flags.Encode()
	decoded := DecodeRawTCPFlags(encoded)
	if decoded != flags {
		t.Fatalf("decode mismatch: got %+v want %+v", decoded, flags)
	}

	// Full flag test
	full, err := ParseRawTCPFlags("FSRPAUECN")
	if err != nil {
		t.Fatalf("ParseRawTCPFlags full failed: %v", err)
	}
	if full.String() != "FSRPAUECN" {
		t.Fatalf("unexpected full string: %s", full.String())
	}

	// Error test
	if _, err := ParseRawTCPFlags("PX"); err == nil {
		t.Fatalf("expected error on invalid flag character")
	}
}

func TestRawPacketMessage_PingPong(t *testing.T) {
	ping := &RawPacketMessage{Type: MsgPing}
	b, err := ping.Encode()
	if err != nil {
		t.Fatalf("encode ping failed: %v", err)
	}
	if len(b) != HeaderLen {
		t.Fatalf("unexpected ping length: %d", len(b))
	}

	decoded, err := DecodeRawPacketMessage(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("decode ping failed: %v", err)
	}
	if decoded.Type != MsgPing {
		t.Fatalf("unexpected decoded type: 0x%02x", decoded.Type)
	}

	pong := &RawPacketMessage{Type: MsgPong}
	bPong, err := pong.Encode()
	if err != nil {
		t.Fatalf("encode pong failed: %v", err)
	}
	decodedPong, n, err := DecodeRawPacketBytes(bPong)
	if err != nil {
		t.Fatalf("decode pong bytes failed: %v", err)
	}
	if n != HeaderLen || decodedPong.Type != MsgPong {
		t.Fatalf("unexpected decoded pong: %+v, n=%d", decodedPong, n)
	}
}

func TestRawPacketMessage_TcpAndUdp(t *testing.T) {
	msgTcp := &RawPacketMessage{
		Type: MsgTCP,
		Target: &TargetEndpoint{
			Host: "tunnel.edge.cloudflare.com",
			Port: 8443,
		},
	}
	b, err := msgTcp.Encode()
	if err != nil {
		t.Fatalf("encode tcp failed: %v", err)
	}

	decoded, n, err := DecodeRawPacketBytes(b)
	if err != nil {
		t.Fatalf("decode tcp failed: %v", err)
	}
	if n != len(b) {
		t.Fatalf("consumed mismatch: got %d want %d", n, len(b))
	}
	if decoded.Target == nil || decoded.Target.Host != "tunnel.edge.cloudflare.com" || decoded.Target.Port != 8443 {
		t.Fatalf("unexpected decoded target: %+v", decoded.Target)
	}

	msgUdp := &RawPacketMessage{
		Type: MsgUDP,
		Target: &TargetEndpoint{
			Host: "1.1.1.1",
			Port: 53,
		},
	}
	bUdp, err := msgUdp.Encode()
	if err != nil {
		t.Fatalf("encode udp failed: %v", err)
	}
	decodedUdp, err := DecodeRawPacketMessage(bytes.NewReader(bUdp))
	if err != nil {
		t.Fatalf("decode udp failed: %v", err)
	}
	if decodedUdp.Target.Host != "1.1.1.1" || decodedUdp.Target.Port != 53 {
		t.Fatalf("unexpected decoded udp: %+v", decodedUdp.Target)
	}
}

func TestRawPacketMessage_Tcpf(t *testing.T) {
	flags := []RawTCPFlags{
		{SYN: true},
		{SYN: true, ACK: true},
		{PSH: true, ACK: true},
	}
	msg := &RawPacketMessage{
		Type:  MsgTCPF,
		Flags: flags,
	}

	b, err := msg.Encode()
	if err != nil {
		t.Fatalf("encode tcpf failed: %v", err)
	}

	decoded, n, err := DecodeRawPacketBytes(b)
	if err != nil {
		t.Fatalf("decode tcpf failed: %v", err)
	}
	if n != len(b) {
		t.Fatalf("byte count mismatch: %d != %d", n, len(b))
	}
	if len(decoded.Flags) != 3 {
		t.Fatalf("unexpected flags length: %d", len(decoded.Flags))
	}
	if !decoded.Flags[0].SYN || decoded.Flags[0].ACK {
		t.Fatalf("unexpected first flag: %+v", decoded.Flags[0])
	}
	if !decoded.Flags[1].SYN || !decoded.Flags[1].ACK {
		t.Fatalf("unexpected second flag: %+v", decoded.Flags[1])
	}
	if !decoded.Flags[2].PSH || !decoded.Flags[2].ACK {
		t.Fatalf("unexpected third flag: %+v", decoded.Flags[2])
	}
}

func TestComputeTCPChecksum(t *testing.T) {
	src := net.ParseIP("192.168.1.100")
	dst := net.ParseIP("10.0.0.1")
	payload := []byte{0x04, 0x00, 0x1f, 0x90, 0x00, 0x00, 0x00, 0x01, 0x50, 0x02, 0xff, 0xff}

	csum := ComputeTCPChecksum(src, dst, payload)
	if csum == 0 {
		t.Fatalf("checksum is zero")
	}

	// IPv6 checksum
	src6 := net.ParseIP("2001:db8::1")
	dst6 := net.ParseIP("2001:db8::2")
	csum6 := ComputeTCPChecksum(src6, dst6, payload)
	if csum6 == 0 {
		t.Fatalf("ipv6 checksum is zero")
	}
}

func TestHashFunctions(t *testing.T) {
	ip4 := net.ParseIP("127.0.0.1")
	h1 := HashIPAddr(ip4, 8080)
	h2 := HashIPAddr(ip4, 8081)
	if h1 == h2 {
		t.Fatalf("expected different hashes for different ports")
	}

	p1 := HashAddrPair("127.0.0.1:1080", "1.1.1.1:53")
	p2 := HashAddrPair("127.0.0.1:1080", "1.1.1.1:53")
	if p1 != p2 {
		t.Fatalf("hash must be deterministic")
	}
}

func TestKCPProfiles(t *testing.T) {
	fast := NewKCPTransportProfile("fast")
	if fast.Interval != 30 || fast.DSCP != 46 {
		t.Fatalf("unexpected fast profile: %+v", fast)
	}

	fast2 := NewKCPTransportProfile("fast2")
	if fast2.NoDelay != 1 || fast2.Interval != 20 || !fast2.AckNoDelay {
		t.Fatalf("unexpected fast2 profile: %+v", fast2)
	}

	fast3 := NewKCPTransportProfile("fast3")
	if fast3.Interval != 10 || fast3.WDelay {
		t.Fatalf("unexpected fast3 profile: %+v", fast3)
	}
}
