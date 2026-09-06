// Copyright 2024 LumiNet. Use of this source code is governed by the MIT license.
// Package dns provides wire-level RFC 1035 DNS probing, Iranian and hostile
// censorship redirect detection (e.g. 10.10.34.0/24), clean resolver rescue scanning,
// and persistent clean DNS resolver vault management.
// Originates from RedCloud Windows core and adapted for LumiNet.

package dns

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// DnsProbeResult details the outcome of a DNS wire-level verification probe.
type DnsProbeResult struct {
	ServerIP     string        `json:"server_ip"`
	Latency      time.Duration `json:"latency"`
	LatencyMs    int64         `json:"latency_ms"`
	ResolvedIPs  []string      `json:"resolved_ips"`
	IsPoisoned   bool          `json:"is_poisoned"`
	PoisonReason string        `json:"poison_reason,omitempty"`
	Success      bool          `json:"success"`
}

// IsPoisonedIP checks if an IP belongs to known censorship redirect pages, private,
// loopback, or invalid address spaces returned by hostile DNS filtering.
func IsPoisonedIP(ip net.IP) (bool, string) {
	if ip == nil {
		return true, "nil IP"
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		// IPv6 filtering checks
		if ip.IsLoopback() {
			return true, "Bogus IPv6 Loopback"
		}
		if ip.IsUnspecified() {
			return true, "Bogus IPv6 Unspecified"
		}
		return false, ""
	}

	// Iranian National Filtering redirect page: 10.10.34.0/24
	if ipv4[0] == 10 && ipv4[1] == 10 && ipv4[2] == 34 {
		return true, "Iranian Censorship Redirect Page (10.10.34.0/24)"
	}

	// RFC 1918 Class A: 10.0.0.0/8
	if ipv4[0] == 10 {
		return true, "Bogus Private RFC 1918 Class A (10.0.0.0/8)"
	}

	// Loopback: 127.0.0.0/8
	if ipv4[0] == 127 {
		return true, "Bogus Loopback Address (127.0.0.0/8)"
	}

	// Current network / zero: 0.0.0.0/8
	if ipv4[0] == 0 {
		return true, "Bogus Unspecified Address (0.0.0.0/8)"
	}

	// RFC 1918 Class C: 192.168.0.0/16
	if ipv4[0] == 192 && ipv4[1] == 168 {
		return true, "Bogus Private RFC 1918 Class C (192.168.0.0/16)"
	}

	// RFC 1918 Class B: 172.16.0.0 - 172.31.255.255
	if ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31 {
		return true, "Bogus Private RFC 1918 Class B (172.16.0.0/12)"
	}

	// CGNAT: 100.64.0.0/10 (100.64.0.0 to 100.127.255.255)
	if ipv4[0] == 100 && ipv4[1] >= 64 && ipv4[1] <= 127 {
		return true, "Bogus CGNAT RFC 6598 (100.64.0.0/10)"
	}

	// Link-local: 169.254.0.0/16
	if ipv4[0] == 169 && ipv4[1] == 254 {
		return true, "Bogus Link-Local RFC 3927 (169.254.0.0/16)"
	}

	// Benchmarking: 198.18.0.0/15 (198.18.0.0 to 198.19.255.255)
	if ipv4[0] == 198 && (ipv4[1] == 18 || ipv4[1] == 19) {
		return true, "Bogus Benchmarking RFC 2544 (198.18.0.0/15)"
	}

	// Broadcast
	if ipv4.Equal(net.IPv4bcast) {
		return true, "Bogus Broadcast Address (255.255.255.255)"
	}

	// Multicast: 224.0.0.0/4
	if ipv4[0] >= 224 && ipv4[0] <= 239 {
		return true, "Bogus Multicast Address (224.0.0.0/4)"
	}

	return false, ""
}

// BuildRFC1035Query constructs an RFC 1035 Type-A query packet.
func BuildRFC1035Query(domain string, txID uint16) ([]byte, error) {
	if len(domain) == 0 || len(domain) > 253 {
		return nil, errors.New("invalid domain length")
	}

	buf := new(bytes.Buffer)

	// Header (12 bytes)
	// Transaction ID
	if err := binary.Write(buf, binary.BigEndian, txID); err != nil {
		return nil, err
	}
	// Flags: 0x0100 (Standard query, RD = 1)
	buf.Write([]byte{0x01, 0x00})
	// QDCOUNT: 1
	buf.Write([]byte{0x00, 0x01})
	// ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: 0
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Question: QNAME
	domain = strings.TrimSuffix(domain, ".")
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid label length in domain %q", domain)
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0x00) // Terminating null byte

	// QTYPE: A (1)
	buf.Write([]byte{0x00, 0x01})
	// QCLASS: IN (1)
	buf.Write([]byte{0x00, 0x01})

	return buf.Bytes(), nil
}

// ParseRFC1035Response parses a raw DNS response and returns answer IPv4s.
func ParseRFC1035Response(data []byte, expectedTxID uint16) ([]net.IP, error) {
	if len(data) < 12 {
		return nil, errors.New("dns response too short for header")
	}

	txID := binary.BigEndian.Uint16(data[0:2])
	if expectedTxID != 0 && txID != expectedTxID {
		return nil, fmt.Errorf("transaction ID mismatch: got %d, expected %d", txID, expectedTxID)
	}

	flags := binary.BigEndian.Uint16(data[2:4])
	qr := (flags >> 15) & 0x01
	if qr == 0 {
		return nil, errors.New("not a response packet (QR=0)")
	}

	rcode := flags & 0x0F
	if rcode != 0 {
		return nil, fmt.Errorf("dns response error rcode: %d", rcode)
	}

	qdcount := int(binary.BigEndian.Uint16(data[4:6]))
	ancount := int(binary.BigEndian.Uint16(data[6:8]))

	if ancount == 0 {
		return []net.IP{}, nil
	}

	offset := 12
	// Skip Question section
	for i := 0; i < qdcount; i++ {
		nextOffset, err := skipDNSName(data, offset)
		if err != nil {
			return nil, err
		}
		offset = nextOffset + 4 // QTYPE(2) + QCLASS(2)
		if offset > len(data) {
			return nil, errors.New("response truncated in question section")
		}
	}

	var ips []net.IP
	// Parse Answer section
	for i := 0; i < ancount; i++ {
		if offset >= len(data) {
			break
		}
		nextOffset, err := skipDNSName(data, offset)
		if err != nil {
			return nil, err
		}
		offset = nextOffset
		if offset+10 > len(data) {
			return nil, errors.New("response truncated in answer header")
		}

		rtype := binary.BigEndian.Uint16(data[offset : offset+2])
		rdlength := int(binary.BigEndian.Uint16(data[offset+8 : offset+10]))
		offset += 10

		if offset+rdlength > len(data) {
			return nil, errors.New("response truncated in rdata")
		}

		// TYPE A = 1, RDLENGTH = 4
		if rtype == 1 && rdlength == 4 {
			ip := net.IPv4(data[offset], data[offset+1], data[offset+2], data[offset+3])
			ips = append(ips, ip)
		}

		offset += rdlength
	}

	return ips, nil
}

func skipDNSName(data []byte, offset int) (int, error) {
	jumps := 0
	for offset < len(data) {
		length := int(data[offset])
		if length == 0 {
			return offset + 1, nil
		}
		if (length & 0xC0) == 0xC0 {
			if offset+2 > len(data) {
				return 0, errors.New("truncated compression pointer")
			}
			return offset + 2, nil
		}
		offset += 1 + length
		jumps++
		if jumps > 128 {
			return 0, errors.New("too many label jumps")
		}
	}
	return 0, errors.New("unexpected end of packet reading name")
}

// VerifyDnsResolution performs a live UDP query against a target DNS server.
func VerifyDnsResolution(ctx context.Context, serverIP net.IP, testDomain string, timeout time.Duration) *DnsProbeResult {
	result := &DnsProbeResult{
		ServerIP: serverIP.String(),
	}

	nBig, err := rand.Int(rand.Reader, big.NewInt(65535))
	txID := uint16(1)
	if err == nil {
		txID = uint16(nBig.Int64() + 1)
	}

	query, err := BuildRFC1035Query(testDomain, txID)
	if err != nil {
		result.PoisonReason = err.Error()
		return result
	}

	dialer := &net.Dialer{Timeout: timeout}
	target := net.JoinHostPort(serverIP.String(), "53")

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "udp", target)
	if err != nil {
		result.PoisonReason = fmt.Sprintf("Dial failed: %v", err)
		return result
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(query); err != nil {
		result.PoisonReason = fmt.Sprintf("Write failed: %v", err)
		return result
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	result.Latency = time.Since(start)
	result.LatencyMs = result.Latency.Milliseconds()

	if err != nil {
		result.PoisonReason = fmt.Sprintf("Read failed: %v", err)
		return result
	}

	if n < 32 {
		result.IsPoisoned = true
		result.PoisonReason = fmt.Sprintf("Response too short (%d bytes)", n)
		return result
	}

	ips, err := ParseRFC1035Response(buf[:n], txID)
	if err != nil {
		result.IsPoisoned = true
		result.PoisonReason = fmt.Sprintf("Parse error / forged packet: %v", err)
		return result
	}

	for _, ip := range ips {
		result.ResolvedIPs = append(result.ResolvedIPs, ip.String())
		if isPoisoned, reason := IsPoisonedIP(ip); isPoisoned {
			result.IsPoisoned = true
			result.PoisonReason = fmt.Sprintf("Poisoned IP %s: %s", ip.String(), reason)
			return result
		}
	}

	result.Success = true
	return result
}

// RunDnsRescueScan runs concurrent verification across multiple DNS server candidates.
func RunDnsRescueScan(ctx context.Context, candidates []net.IP, testDomain string, timeout time.Duration) []*DnsProbeResult {
	var wg sync.WaitGroup
	results := make([]*DnsProbeResult, len(candidates))

	for i, candidate := range candidates {
		wg.Add(1)
		go func(idx int, s net.IP) {
			defer wg.Done()
			results[idx] = VerifyDnsResolution(ctx, s, testDomain, timeout)
		}(i, candidate)
	}

	wg.Wait()
	return results
}

// VerifiedDnsRecord represents a verified clean resolver in the vault.
type VerifiedDnsRecord struct {
	IP                   string    `json:"ip"`
	LatencyMs            int64     `json:"latency_ms"`
	VerifiedAt           time.Time `json:"verified_at"`
	ProviderLabel        string    `json:"provider_label"`
	ConsecutiveSuccesses int       `json:"consecutive_successes"`
	IsClean              bool      `json:"is_clean"`
}

// DnsVault tracks and persists verified clean DNS servers.
type DnsVault struct {
	mu      sync.RWMutex
	records map[string]*VerifiedDnsRecord
}

// NewDnsVault creates an empty DnsVault.
func NewDnsVault() *DnsVault {
	return &DnsVault{
		records: make(map[string]*VerifiedDnsRecord),
	}
}

// UpdateRecord records the result of a DNS verification.
func (v *DnsVault) UpdateRecord(ip string, latencyMs int64, isClean bool, label string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	rec, exists := v.records[ip]
	if exists {
		rec.LatencyMs = latencyMs
		rec.VerifiedAt = time.Now()
		rec.IsClean = isClean
		if isClean {
			rec.ConsecutiveSuccesses++
		} else {
			rec.ConsecutiveSuccesses = 0
		}
		if label != "" {
			rec.ProviderLabel = label
		}
	} else {
		succ := 0
		if isClean {
			succ = 1
		}
		v.records[ip] = &VerifiedDnsRecord{
			IP:                   ip,
			LatencyMs:            latencyMs,
			VerifiedAt:           time.Now(),
			ProviderLabel:        label,
			ConsecutiveSuccesses: succ,
			IsClean:              isClean,
		}
	}
}

// RankCleanResolvers returns all clean DNS resolvers sorted by latency ascending.
func (v *DnsVault) RankCleanResolvers() []*VerifiedDnsRecord {
	v.mu.RLock()
	defer v.mu.RUnlock()

	var clean []*VerifiedDnsRecord
	for _, rec := range v.records {
		if rec.IsClean && rec.ConsecutiveSuccesses > 0 {
			clean = append(clean, rec)
		}
	}

	sort.Slice(clean, func(i, j int) bool {
		return clean[i].LatencyMs < clean[j].LatencyMs
	})

	return clean
}

// GetFastestClean returns the fastest clean DNS resolver, or nil if none found.
func (v *DnsVault) GetFastestClean() *VerifiedDnsRecord {
	clean := v.RankCleanResolvers()
	if len(clean) == 0 {
		return nil
	}
	return clean[0]
}

// ToJSON exports the vault state to JSON.
func (v *DnsVault) ToJSON() ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return json.MarshalIndent(v.records, "", "  ")
}

// LoadJSON restores vault state from JSON.
func (v *DnsVault) LoadJSON(data []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return json.Unmarshal(data, &v.records)
}
