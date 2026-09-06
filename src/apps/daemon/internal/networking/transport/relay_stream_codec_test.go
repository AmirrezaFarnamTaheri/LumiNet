package transport

import (
	"bytes"
	"testing"
)

func TestRelayStreamCodec_V1_TCP(t *testing.T) {
	hdr := &RelayStreamHeader{
		Network: RelayNetworkTCP,
		Host:    "1.1.1.1",
		Port:    443,
	}

	encoded := hdr.EncodeV1()
	expected := []byte("tcp@1.1.1.1$443\r")
	if !bytes.Equal(encoded, expected) {
		t.Fatalf("expected %q, got %q", expected, encoded)
	}

	decoded, consumed, err := DecodeV1(encoded)
	if err != nil {
		t.Fatalf("decode v1 failed: %v", err)
	}
	if consumed != len(encoded) {
		t.Errorf("expected consumed %d, got %d", len(encoded), consumed)
	}
	if decoded.Network != RelayNetworkTCP || decoded.Host != "1.1.1.1" || decoded.Port != 443 {
		t.Errorf("unexpected decoded content: %+v", decoded)
	}
}

func TestRelayStreamCodec_V1_UDP(t *testing.T) {
	hdr := &RelayStreamHeader{
		Network: RelayNetworkUDP,
		Host:    "dns.google",
		Port:    53,
	}

	encoded := hdr.EncodeV1()
	decoded, consumed, err := DecodeV1(encoded)
	if err != nil {
		t.Fatalf("decode v1 failed: %v", err)
	}
	if consumed != len(encoded) {
		t.Errorf("consumed mismatch: %d != %d", consumed, len(encoded))
	}
	if decoded.Network != RelayNetworkUDP || decoded.Host != "dns.google" || decoded.Port != 53 {
		t.Errorf("decoded mismatch: %+v", decoded)
	}
}

func TestRelayStreamCodec_V2(t *testing.T) {
	hdr := &RelayStreamHeader{
		Network: RelayNetworkTCP,
		Host:    "proxy.edge.internal",
		Port:    8443,
	}

	encoded := hdr.EncodeV2()
	if len(encoded) != 6+len("proxy.edge.internal") {
		t.Fatalf("unexpected v2 length: %d", len(encoded))
	}
	if string(encoded[:2]) != "R2" {
		t.Fatalf("invalid magic: %v", encoded[:2])
	}

	decoded, consumed, err := DecodeV2(encoded)
	if err != nil {
		t.Fatalf("decode v2 failed: %v", err)
	}
	if consumed != len(encoded) {
		t.Errorf("consumed mismatch: %d != %d", consumed, len(encoded))
	}
	if decoded.Network != RelayNetworkTCP || decoded.Host != "proxy.edge.internal" || decoded.Port != 8443 {
		t.Errorf("decoded mismatch: %+v", decoded)
	}
}
