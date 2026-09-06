package transport

import (
	"bytes"
	"testing"
)

func TestPppTlsTunnelCodec(t *testing.T) {
	codecHDLC := NewPppTlsTunnelCodec(true)
	codecPlain := NewPppTlsTunnelCodec(false)

	payload := []byte("4500003c123440004006...") // sample IP packet

	// Test with HDLC
	encodedHDLC := codecHDLC.EncodeFrame(PppProtocolIPv4, payload)
	protoHDLC, recoveredHDLC, err := codecHDLC.DecodeFrame(encodedHDLC)
	if err != nil {
		t.Fatalf("failed to decode HDLC frame: %v", err)
	}
	if protoHDLC != PppProtocolIPv4 {
		t.Fatalf("expected IPv4 proto, got %x", protoHDLC)
	}
	if !bytes.Equal(recoveredHDLC, payload) {
		t.Fatalf("payload mismatch with HDLC")
	}

	// Test without HDLC
	encodedPlain := codecPlain.EncodeFrame(PppProtocolIPv6, payload)
	protoPlain, recoveredPlain, err := codecPlain.DecodeFrame(encodedPlain)
	if err != nil {
		t.Fatalf("failed to decode plain frame: %v", err)
	}
	if protoPlain != PppProtocolIPv6 {
		t.Fatalf("expected IPv6 proto, got %x", protoPlain)
	}
	if !bytes.Equal(recoveredPlain, payload) {
		t.Fatalf("payload mismatch without HDLC")
	}
}
