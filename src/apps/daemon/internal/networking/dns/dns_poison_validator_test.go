package dns

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestIsPoisonedIP(t *testing.T) {
	cases := []struct {
		ip       string
		poisoned bool
	}{
		{"10.10.34.1", true},
		{"10.10.34.254", true},
		{"10.0.0.1", true},
		{"127.0.0.1", true},
		{"0.0.0.0", true},
		{"192.168.1.1", true},
		{"172.16.0.1", true},
		{"172.31.255.254", true},
		{"172.32.0.1", false},
		{"100.64.0.1", true},
		{"100.127.255.254", true},
		{"100.128.0.1", false},
		{"169.254.1.1", true},
		{"198.18.0.1", true},
		{"198.19.255.254", true},
		{"255.255.255.255", true},
		{"224.0.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"142.250.190.46", false},
	}

	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		poisoned, reason := IsPoisonedIP(ip)
		if poisoned != tc.poisoned {
			t.Errorf("IsPoisonedIP(%s) = %v (reason: %s); want %v", tc.ip, poisoned, reason, tc.poisoned)
		}
	}
}

func TestBuildAndParseRFC1035(t *testing.T) {
	txID := uint16(0x5678)
	domain := "example.com"

	query, err := BuildRFC1035Query(domain, txID)
	if err != nil {
		t.Fatalf("BuildRFC1035Query failed: %v", err)
	}

	if len(query) < 12 {
		t.Fatalf("Query too short: %d", len(query))
	}

	// Synthesize valid response
	resp := new(bytes.Buffer)
	_ = binary.Write(resp, binary.BigEndian, txID)
	resp.Write([]byte{0x81, 0x80}) // Flags: response, no error
	_ = binary.Write(resp, binary.BigEndian, uint16(1)) // QDCOUNT = 1
	_ = binary.Write(resp, binary.BigEndian, uint16(1)) // ANCOUNT = 1
	_ = binary.Write(resp, binary.BigEndian, uint16(0)) // NSCOUNT = 0
	_ = binary.Write(resp, binary.BigEndian, uint16(0)) // ARCOUNT = 0

	// Copy question section from query
	resp.Write(query[12:])

	// Answer 1: pointer 0xC00C, TYPE A (1), CLASS IN (1), TTL 300, RDLENGTH 4, IP 93.184.216.34
	resp.Write([]byte{0xC0, 0x0C})
	resp.Write([]byte{0x00, 0x01, 0x00, 0x01})
	resp.Write([]byte{0x00, 0x00, 0x01, 0x2C})
	resp.Write([]byte{0x00, 0x04})
	resp.Write([]byte{93, 184, 216, 34})

	ips, err := ParseRFC1035Response(resp.Bytes(), txID)
	if err != nil {
		t.Fatalf("ParseRFC1035Response failed: %v", err)
	}

	if len(ips) != 1 {
		t.Fatalf("Expected 1 IP, got %d", len(ips))
	}

	if !ips[0].Equal(net.IPv4(93, 184, 216, 34)) {
		t.Fatalf("Unexpected IP: %v", ips[0])
	}
}

func TestDnsVault(t *testing.T) {
	vault := NewDnsVault()

	vault.UpdateRecord("1.1.1.1", 35, true, "Cloudflare")
	vault.UpdateRecord("8.8.8.8", 20, true, "Google")
	vault.UpdateRecord("10.10.34.1", 5, false, "Poisoned")

	clean := vault.RankCleanResolvers()
	if len(clean) != 2 {
		t.Fatalf("Expected 2 clean resolvers, got %d", len(clean))
	}

	if clean[0].IP != "8.8.8.8" {
		t.Fatalf("Expected 8.8.8.8 first, got %s", clean[0].IP)
	}

	fastest := vault.GetFastestClean()
	if fastest == nil || fastest.IP != "8.8.8.8" {
		t.Fatalf("Expected fastest 8.8.8.8, got %v", fastest)
	}

	data, err := vault.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	newVault := NewDnsVault()
	if err := newVault.LoadJSON(data); err != nil {
		t.Fatalf("LoadJSON failed: %v", err)
	}

	if len(newVault.RankCleanResolvers()) != 2 {
		t.Fatalf("Restored vault clean count mismatch")
	}
}
