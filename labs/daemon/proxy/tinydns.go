package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
)

// DNS type and class constants used by the tinydoh subsystem.
const (
	dnsTypeA   uint16 = 1
	dnsClassIN uint16 = 1
)

// buildDNSQuery constructs a minimal DNS wire-format query for fqdn with the
// given qtype (e.g. dnsTypeA). A fixed transaction ID of 0x0001 is used.
func buildDNSQuery(fqdn string, qtype uint16) ([]byte, error) {
	var buf []byte

	// Transaction ID
	buf = append(buf, 0x00, 0x01)
	// Flags: QR=0, RD=1
	buf = append(buf, 0x01, 0x00)
	// QDCOUNT=1
	buf = append(buf, 0x00, 0x01)
	// ANCOUNT, NSCOUNT, ARCOUNT = 0
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	// QNAME: encode each label
	fqdn = strings.TrimSuffix(fqdn, ".")
	for _, label := range strings.Split(fqdn, ".") {
		if len(label) > 63 {
			return nil, fmt.Errorf("label too long: %q", label)
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00) // root label

	// QTYPE
	qtb := make([]byte, 2)
	binary.BigEndian.PutUint16(qtb, qtype)
	buf = append(buf, qtb...)

	// QCLASS IN
	qcb := make([]byte, 2)
	binary.BigEndian.PutUint16(qcb, dnsClassIN)
	buf = append(buf, qcb...)

	return buf, nil
}

// parseDNSResponse parses a DNS wire-format response and returns the IP
// addresses found in answer records matching qtype.
func parseDNSResponse(data []byte, qtype uint16) ([]net.IP, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("dns response too short: %d bytes", len(data))
	}

	ancount := binary.BigEndian.Uint16(data[6:8])
	qdcount := binary.BigEndian.Uint16(data[4:6])

	// Skip past the header and question section
	offset := 12
	for i := 0; i < int(qdcount); i++ {
		// Skip QNAME
		var err error
		offset, err = skipName(data, offset)
		if err != nil {
			return nil, err
		}
		offset += 4 // QTYPE + QCLASS
	}

	var ips []net.IP
	for i := 0; i < int(ancount); i++ {
		var err error
		offset, err = skipName(data, offset)
		if err != nil {
			return nil, err
		}
		if offset+10 > len(data) {
			return nil, fmt.Errorf("answer record truncated at offset %d", offset)
		}
		rrType := binary.BigEndian.Uint16(data[offset : offset+2])
		// skip type(2) + class(2) + ttl(4)
		offset += 8
		rdLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if offset+rdLen > len(data) {
			return nil, fmt.Errorf("rdata truncated")
		}
		if rrType == qtype {
			if qtype == dnsTypeA && rdLen == 4 {
				ip := make(net.IP, 4)
				copy(ip, data[offset:offset+4])
				ips = append(ips, ip)
			}
		}
		offset += rdLen
	}
	return ips, nil
}

// skipName advances past a DNS name (with possible pointer compression) and
// returns the new offset after the name.
func skipName(data []byte, offset int) (int, error) {
	for {
		if offset >= len(data) {
			return 0, fmt.Errorf("name parse overrun at offset %d", offset)
		}
		length := int(data[offset])
		if length == 0 {
			return offset + 1, nil
		}
		// Pointer compression: top two bits set
		if length&0xC0 == 0xC0 {
			return offset + 2, nil
		}
		offset += 1 + length
	}
}

// OfflineDNSCache is a simple in-memory cache mapping hostnames to IP addresses.
// It is used for static/offline resolution without a DNS server.
type OfflineDNSCache struct {
	mu      sync.RWMutex
	entries map[string]net.IP
}

// NewOfflineDNSCache creates a new OfflineDNSCache pre-populated with the
// provided entries (hostname -> dotted-decimal IP string).
func NewOfflineDNSCache(entries map[string]string) *OfflineDNSCache {
	c := &OfflineDNSCache{
		entries: make(map[string]net.IP, len(entries)),
	}
	for host, ipStr := range entries {
		if ip := net.ParseIP(ipStr); ip != nil {
			c.entries[host] = ip
		}
	}
	return c
}

// Lookup returns the cached IP for host, or nil if not found.
func (c *OfflineDNSCache) Lookup(host string) net.IP {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.entries[host]
}

// Set stores or overwrites an IP for host.
func (c *OfflineDNSCache) Set(host string, ip net.IP) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[host] = ip
}
