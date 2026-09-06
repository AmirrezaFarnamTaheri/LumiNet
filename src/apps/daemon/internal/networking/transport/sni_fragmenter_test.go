package transport

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func buildTestClientHello(sni string) []byte {
	sniBytes := []byte(sni)

	// Server Name extension
	extSNI := make([]byte, 0, 9+len(sniBytes))
	extSNI = append(extSNI, 0x00, 0x00) // ext type 0x0000
	extLen := 5 + len(sniBytes)
	extSNI = binary.BigEndian.AppendUint16(extSNI, uint16(extLen))
	listLen := 3 + len(sniBytes)
	extSNI = binary.BigEndian.AppendUint16(extSNI, uint16(listLen))
	extSNI = append(extSNI, 0x00) // Hostname type
	extSNI = binary.BigEndian.AppendUint16(extSNI, uint16(len(sniBytes)))
	extSNI = append(extSNI, sniBytes...)

	// ALPN extension
	extALPN := []byte{0x00, 0x10, 0x00, 0x03, 0x02, 'h', '2'}

	extensions := append(extSNI, extALPN...)

	// Handshake body
	var body []byte
	body = append(body, 0x03, 0x03) // TLS 1.2 client version
	body = append(body, make([]byte, 32)...) // Random
	body = append(body, 0x00) // Session ID len 0
	body = append(body, 0x00, 0x02, 0x13, 0x01) // 1 cipher suite (TLS_AES_128_GCM_SHA256)
	body = append(body, 0x01, 0x00) // Compression: null
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)

	// Handshake header
	var handshake []byte
	handshake = append(handshake, 0x01) // ClientHello
	handshake = append(handshake, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)

	// TLS Record header
	var record []byte
	record = append(record, 0x16, 0x03, 0x01) // Handshake, TLS 1.0 record version
	record = binary.BigEndian.AppendUint16(record, uint16(len(handshake)))
	record = append(record, handshake...)

	return record
}

func TestSniExtractionAndLocation(t *testing.T) {
	packet := buildTestClientHello("cloudflare.com")
	fragmenter := &SniFragmenter{}

	sni, err := fragmenter.ExtractSNI(packet)
	if err != nil {
		t.Fatalf("ExtractSNI failed: %v", err)
	}
	if sni != "cloudflare.com" {
		t.Fatalf("Expected cloudflare.com, got %s", sni)
	}

	start, end, locatedName, err := fragmenter.LocateSNI(packet)
	if err != nil {
		t.Fatalf("LocateSNI failed: %v", err)
	}
	if locatedName != "cloudflare.com" {
		t.Fatalf("Expected cloudflare.com, got %s", locatedName)
	}
	if string(packet[start:end]) != "cloudflare.com" {
		t.Fatalf("Byte slice mismatch at [%d:%d]: %s", start, end, string(packet[start:end]))
	}
}

func TestFragmentPlanningTotalBytesAndContinuity(t *testing.T) {
	packet := buildTestClientHello("api.github.com")
	fragmenter := &SniFragmenter{}
	cfg := DefaultSniFragmentConfig()

	plan := fragmenter.PlanFragments(packet, cfg)
	if plan.DetectedSNI != "api.github.com" {
		t.Fatalf("Expected detected SNI api.github.com, got %s", plan.DetectedSNI)
	}
	if plan.TotalBytes != len(packet) {
		t.Fatalf("TotalBytes mismatch: expected %d, got %d", len(packet), plan.TotalBytes)
	}

	var reconstructed []byte
	var hasBefore, hasSni, hasAfter bool
	for _, s := range plan.Slices {
		reconstructed = append(reconstructed, s.Payload...)
		if s.Zone == "before_sni" {
			hasBefore = true
		} else if s.Zone == "sni" {
			hasSni = true
		} else if s.Zone == "after_sni" {
			hasAfter = true
		}
	}

	if !hasBefore || !hasSni || !hasAfter {
		t.Fatalf("Expected slices across before_sni, sni, and after_sni zones")
	}

	if !bytes.Equal(reconstructed, packet) {
		t.Fatalf("Reconstructed packet does not match original ClientHello byte-for-byte")
	}
}

func TestPassthroughNonTLS(t *testing.T) {
	rawHTTP := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	fragmenter := &SniFragmenter{}
	cfg := DefaultSniFragmentConfig()

	plan := fragmenter.PlanFragments(rawHTTP, cfg)
	if plan.DetectedSNI != "" {
		t.Fatalf("Expected empty detected SNI for HTTP request")
	}
	if len(plan.Slices) != 1 {
		t.Fatalf("Expected 1 passthrough slice, got %d", len(plan.Slices))
	}
	if plan.Slices[0].Zone != "passthrough" {
		t.Fatalf("Expected passthrough zone, got %s", plan.Slices[0].Zone)
	}
	if !bytes.Equal(plan.Slices[0].Payload, rawHTTP) {
		t.Fatalf("Passthrough payload corrupted")
	}
}
