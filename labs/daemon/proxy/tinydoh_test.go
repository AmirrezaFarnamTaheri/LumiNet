package proxy

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestBuildDNSQuery(t *testing.T) {
	fqdn := "google.com"
	query, err := buildDNSQuery(fqdn, dnsTypeA)
	if err != nil {
		t.Fatalf("failed to build DNS query: %v", err)
	}
	if len(query) < 12 {
		t.Fatalf("query too short: %d", len(query))
	}
	// Check QTYPE and QCLASS at the end
	qtype := binary.BigEndian.Uint16(query[len(query)-4 : len(query)-2])
	if qtype != dnsTypeA {
		t.Errorf("expected QTYPE A (%d), got %d", dnsTypeA, qtype)
	}
	qclass := binary.BigEndian.Uint16(query[len(query)-2:])
	if qclass != dnsClassIN {
		t.Errorf("expected QCLASS IN (%d), got %d", dnsClassIN, qclass)
	}
}

func TestParseDNSResponse(t *testing.T) {
	// A simple mock DNS response containing an A record for 127.0.0.1
	msg := []byte{
		0x00, 0x01, // ID
		0x81, 0x80, // Flags: QR, RD, RA
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x01, // ANCOUNT: 1
		0x00, 0x00, 0x00, 0x00, // NSCOUNT, ARCOUNT
		// Question
		0x06, 'g', 'o', 'o', 'g', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // Null label
		0x00, 0x01, // QTYPE: A
		0x00, 0x01, // QCLASS: IN
		// Answer
		0xc0, 0x0c, // Name: pointer to offset 12 (google.com)
		0x00, 0x01, // TYPE: A
		0x00, 0x01, // CLASS: IN
		0x00, 0x00, 0x00, 0x3c, // TTL: 60
		0x00, 0x04, // RDLENGTH: 4
		127, 0, 0, 1, // RDATA: 127.0.0.1
	}

	ips, err := parseDNSResponse(msg, dnsTypeA)
	if err != nil {
		t.Fatalf("failed to parse DNS response: %v", err)
	}
	if len(ips) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(ips))
	}
	if !ips[0].Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("expected 127.0.0.1, got %v", ips[0])
	}
}

func TestOfflineDNSCache(t *testing.T) {
	entries := map[string]string{
		"myhost.local": "192.168.1.50",
	}
	cache := NewOfflineDNSCache(entries)
	ip := cache.Lookup("myhost.local")
	if ip == nil {
		t.Fatal("expected cached IP to be found")
	}
	if !ip.Equal(net.IPv4(192, 168, 1, 50)) {
		t.Errorf("expected 192.168.1.50, got %v", ip)
	}

	ipNotFound := cache.Lookup("unknown.local")
	if ipNotFound != nil {
		t.Errorf("expected nil for unknown host, got %v", ipNotFound)
	}

	cache.Set("newhost.local", net.IPv4(10, 0, 0, 1))
	ipNew := cache.Lookup("newhost.local")
	if ipNew == nil || !ipNew.Equal(net.IPv4(10, 0, 0, 1)) {
		t.Errorf("failed to lookup newly set host: %v", ipNew)
	}
}
