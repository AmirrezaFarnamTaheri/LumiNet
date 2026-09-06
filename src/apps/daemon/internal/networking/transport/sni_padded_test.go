package transport

import (
	"encoding/binary"
	"testing"
)

func TestPaddedClientHello_Exact517Bytes(t *testing.T) {
	testDomains := []string{
		"a.co",
		"example.com",
		"gateway.subdomain.target-infrastructure.org",
		"very-long-domain-name-intended-to-test-padding-calculation-integrity.vpn.internal.node.io",
	}

	for _, domain := range testDomains {
		packet, err := BuildPaddedClientHello(domain)
		if err != nil {
			t.Fatalf("failed to build padded ClientHello for %s: %v", domain, err)
		}

		if len(packet) != ClientHelloConstantSize {
			t.Fatalf("expected length %d for domain %s, got %d", ClientHelloConstantSize, domain, len(packet))
		}

		// Verify record header: ContentType Handshake (0x16), Version (0x0301)
		if packet[0] != 0x16 {
			t.Fatalf("expected record type 0x16, got 0x%02X", packet[0])
		}
		if binary.BigEndian.Uint16(packet[1:3]) != 0x0301 {
			t.Fatalf("expected record version 0x0301, got 0x%04X", binary.BigEndian.Uint16(packet[1:3]))
		}

		// Verify record length field matches remaining bytes
		recLen := int(binary.BigEndian.Uint16(packet[3:5]))
		if recLen != ClientHelloConstantSize-5 {
			t.Fatalf("expected record length %d, got %d", ClientHelloConstantSize-5, recLen)
		}

		// Verify Handshake type ClientHello (0x01)
		if packet[5] != 0x01 {
			t.Fatalf("expected handshake type 0x01, got 0x%02X", packet[5])
		}
	}
}

func TestPaddedClientHello_ValidationErrors(t *testing.T) {
	_, err := BuildPaddedClientHello("")
	if err == nil {
		t.Fatal("expected error for empty SNI")
	}

	hugeDomain := ""
	for i := 0; i < 220; i++ {
		hugeDomain += "x"
	}
	hugeDomain += ".com"

	_, err = BuildPaddedClientHello(hugeDomain)
	if err == nil {
		t.Fatal("expected error for SNI exceeding padding budget")
	}
}
