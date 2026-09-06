// Copyright 2024 LumiNet. Use of this source code is governed by the MIT license.
// PYDNS-Scanner battery: a suite of diagnostic checks run against a DNS resolver
// to characterise its capabilities and detect common configuration issues.
// Tests cover DNSSEC validation, DNS hijacking, and EDNS0 support.

package diagnostics

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// DNSScanner runs the diagnostic battery against a target resolver.
type DNSScanner struct {
	ResolverIP   string   // IP:port of the resolver to test.
	Timeout      time.Duration
	KnownGoodIPs []string // IPs considered legitimate for hijack detection.
	// TestTargets is the set of domains to probe.
	TestTargets []string
}

// NewDNSScanner builds a scanner with sensible defaults.
func NewDNSScanner(resolverIP string) *DNSScanner {
	s := &DNSScanner{
		ResolverIP:   resolverIP,
		Timeout:      8 * time.Second,
		KnownGoodIPs: []string{},
		TestTargets: []string{
			"cloudflare.com",
			"google.com",
			"github.com",
		},
	}
	return s
}

// SetTimeout overrides the query timeout.
func (s *DNSScanner) SetTimeout(d time.Duration) { s.Timeout = d }

// AddKnownGoodIP adds an IP to the trusted-IP allowlist used for hijack checks.
func (s *DNSScanner) AddKnownGoodIP(ip string) {
	s.KnownGoodIPs = append(s.KnownGoodIPs, ip)
}

// BatteryResult is the aggregated output of RunBattery.
type BatteryResult struct {
	DNSSEC DNSSECTestResult
	EDNS0  EDNSTestResult
	Hijack  HijackTestResult
	Meta    BatteryMeta
}

// BatteryMeta contains metadata about the battery run itself.
type BatteryMeta struct {
	ResolverIP   string
	Duration     time.Duration
	TargetsCount int
	Errors       []string
}

// RunBattery executes all diagnostic tests concurrently and returns the combined result.
func (s *DNSScanner) RunBattery(ctx context.Context) BatteryResult {
	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	var wg sync.WaitGroup
	var dnssecRes DNSSECTestResult
	var edns0Res EDNSTestResult
	var hijackRes HijackTestResult
	var mu sync.Mutex
	var errors []string

	start := time.Now()

	wg.Add(3)
	go func() {
		defer wg.Done()
		r := s.runDNSSECCheck(ctx)
		mu.Lock()
		dnssecRes = r
		mu.Unlock()
	}()
	go func() {
		defer wg.Done()
		r := s.runEDNS0Check(ctx)
		mu.Lock()
		edns0Res = r
		mu.Unlock()
	}()
	go func() {
		defer wg.Done()
		r := s.runHijackCheck(ctx)
		mu.Lock()
		hijackRes = r
		mu.Unlock()
	}()

	wg.Wait()

	return BatteryResult{
		DNSSEC: dnssecRes,
		EDNS0:  edns0Res,
		Hijack:  hijackRes,
		Meta: BatteryMeta{
			ResolverIP:   s.ResolverIP,
			Duration:     time.Since(start),
			TargetsCount: len(s.TestTargets),
			Errors:       errors,
		},
	}
}

// ---------------------------------------------------------------------------
// DNSSEC test
// ---------------------------------------------------------------------------

// DNSSECTestResult holds the outcome of the DNSSEC capability check.
type DNSSECTestResult struct {
	Secure   bool     // resolver performed DNSSEC validation.
	AD       bool     // AD (authentic data) bit was set in responses.
	CD       bool     // CD (checking disabled) bit observed.
	CDPSkipped bool   // resolver stripped CD (DNSSEC checking disabled) requests.
	Failures []string // domains that failed validation when expected secure.
}

// DNSSECTestDomain is a well-known domain with known DNSSEC status.
var DNSSECTestDomain = "cloudflare.com"

// runDNSSECCheck queries a known-signed domain and inspects the AD bit.
func (s *DNSScanner) runDNSSECCheck(ctx context.Context) DNSSECTestResult {
	// cloudflare.com has a valid DNSSEC chain. Query with DO=1 (DNSSEC OK).
	resp, rtt, err := s.queryDNS(ctx, DNSSECTestDomain, 1, true) // TYPE_A=1, DO=1
	res := DNSSECTestResult{}
	if err != nil {
		res.Failures = append(res.Failures, fmt.Sprintf("DNSSEC query failed: %v", err))
		return res
	}
	_ = rtt // available for future per-test RTT reporting

	if len(resp) < 12 {
		res.Failures = append(res.Failures, "response too short for DNSSEC analysis")
		return res
	}
	// Flags are at bytes 2-3.
	flags := binary.BigEndian.Uint16(resp[2:4])
	// Bit 15 (0x8000): QR (response)
	// Bit 11 (0x0800): RD (recursion desired)
	// Bit 10 (0x0400): RA (recursion available)
	// Bit  7 (0x0080): CD (checking disabled)
	// Bit  5 (0x0020): AD (authentic data)
	res.AD = flags&0x0020 != 0
	res.CD = flags&0x0080 != 0
	res.Secure = res.AD

	// Check for a bogus DNSSEC response using a deliberately invalid signature.
	_, _, err = s.queryDNS(ctx, "valid-secp256k1.nil.dnssec.works.", 1, true)
	if err != nil {
		// A resolver performing validation should either return SERVFAIL or the AD bit clear.
		res.Failures = append(res.Failures, fmt.Sprintf("DNSSEC validation query returned error (expected): %v", err))
	}
	return res
}

// ---------------------------------------------------------------------------
// EDNS0 test
// ---------------------------------------------------------------------------

// EDNSTestResult holds the outcome of the EDNS0 support check.
type EDNSTestResult struct {
	Supported    bool // resolver preserves EDNS0 OPT record in response.
	ResponseSize int  // maximum UDP payload size advertised by the resolver.
	ECS          bool // resolver honoured EDNS0 Client Subnet (ECS).
	Failures     []string
}

// runEDNS0Check sends a query with an EDNS0 OPT record and verifies the response
// carries one back, indicating the resolver understands EDNS0.
func (s *DNSScanner) runEDNS0Check(ctx context.Context) EDNSTestResult {
	res := EDNSTestResult{}
	// Query a well-known domain with DO=1 (DNSSEC OK) + EDNS0 buffer.
	resp, _, err := s.queryDNS(ctx, DNSSECTestDomain, 1, true)
	if err != nil {
		res.Failures = append(res.Failures, fmt.Sprintf("EDNS0 query failed: %v", err))
		return res
	}
	if len(resp) >= 12 {
		// Look for the EDNS0 OPT record in the additional section.
		arCount := int(binary.BigEndian.Uint16(resp[10:12]))
		if arCount > 0 {
			res.Supported = true
		}
	}

	// Also test with a large UDP bufsize request (RFC 6891 §7).
	// Build a minimal query with an EDNS0 option.
	q := s.buildQueryWithEDNS0(DNSSECTestDomain, 4096)
	rawResp, _, err := s.rawQuery(ctx, q)
	if err == nil && len(rawResp) > 12 {
		// Check additional section for OPT record.
		arCount := int(binary.BigEndian.Uint16(rawResp[10:12]))
		if arCount > 0 {
			res.Supported = true
			// Try to extract the bufsize from the OPT record.
			// OPT record starts at offset after question section.
			offset := 12
			qdCount := int(binary.BigEndian.Uint16(rawResp[4:6]))
			for i := 0; i < qdCount && offset < len(rawResp); i++ {
				offset = skipDNSName(rawResp, offset)
				if offset+4 > len(rawResp) {
					break
				}
				offset += 4
			}
			// Now in the additional section; look for TYPE 41 (OPT).
			for i := 0; i < arCount && offset+10 <= len(rawResp); i++ {
				if rawResp[offset]&0xC0 == 0xC0 {
					offset += 2
				} else {
					offset = skipDNSName(rawResp, offset)
				}
				if offset+10 > len(rawResp) {
					break
				}
				qtype := binary.BigEndian.Uint16(rawResp[offset : offset+2])
				if qtype == 41 { // TYPE_OPT
					// RDLENGTH is at offset+8:10.
					rdlen := int(binary.BigEndian.Uint16(rawResp[offset+8 : offset+10]))
					if rdlen >= 11 {
						// Extended RCODE and flags at offset+2:4, UDP payload size at offset+4:6.
						res.ResponseSize = int(binary.BigEndian.Uint16(rawResp[offset+4 : offset+6]))
					}
				}
				offset += 10
				if offset+10 <= len(rawResp) {
					rdlen := int(binary.BigEndian.Uint16(rawResp[offset+8 : offset+10]))
					offset += rdlen
				}
			}
		}
	}
	return res
}

// ---------------------------------------------------------------------------
// Hijack test
// ---------------------------------------------------------------------------

// HijackTestResult holds the outcome of the DNS hijack check.
type HijackTestResult struct {
	Hijacked   bool
	HijackedDomains []string
	SuspiciousDomains []string
	Failures    []string
}

// runHijackCheck queries each target domain and checks whether the resolved IPs
// belong to a known-good set or a recognised sinkhole/filtering range.
func (s *DNSScanner) runHijackCheck(ctx context.Context) HijackTestResult {
	res := HijackTestResult{}
	for _, domain := range s.TestTargets {
		ips, err := s.resolveA(ctx, domain)
		if err != nil {
			res.Failures = append(res.Failures, fmt.Sprintf("hijack check for %s: %v", domain, err))
			continue
		}
		if len(ips) == 0 {
			res.SuspiciousDomains = append(res.SuspiciousDomains, domain)
			continue
		}
		// Check each IP against the known-good list.
		hijacked := false
		for _, ip := range ips {
			if isKnownHijackIP(ip) {
				hijacked = true
				break
			}
			for _, good := range s.KnownGoodIPs {
				if ip == good {
					hijacked = false
					break
				}
			}
		}
		if hijacked {
			res.Hijacked = true
			res.HijackedDomains = append(res.HijackedDomains, domain)
		}
	}
	return res
}

// isKnownHijackIP heuristically flags IPs commonly returned by captive portals
// or DNS-level ad filtering.
func isKnownHijackIP(ip string) bool {
	// Sinkhole ranges used by common tools.
	sinkholes := []string{
		"0.0.0.0",
		"127.0.0.1",
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24", // TEST-NET-3
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range sinkholes {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipnet.Contains(parsed) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Low-level DNS helpers
// ---------------------------------------------------------------------------

// queryDNS performs a single DNS A-query and returns the wire-format response.
func (s *DNSScanner) queryDNS(ctx context.Context, name string, qtype uint16, dnssecOK bool) ([]byte, time.Duration, error) {
	q := s.buildQuery(name, qtype, dnssecOK)
	return s.rawQuery(ctx, q)
}

func (s *DNSScanner) buildQuery(name string, qtype uint16, dnssecOK bool) []byte {
	var buf []byte
	buf = append(buf, 0x00, 0x01) // TXID
	buf = append(buf, 0x01, 0x00) // RD=1
	buf = append(buf, 0x00, 0x01) // QDCOUNT=1
	buf = append(buf, 0x00, 0x00) // ANCOUNT, NSCOUNT
	if dnssecOK {
		buf = append(buf, 0x00, 0x01) // ARCOUNT=1 (OPT)
	} else {
		buf = append(buf, 0x00, 0x00)
	}
	// Encode name.
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0x00) // root
	buf = append(buf, 0x00) // high byte of QTYPE
	buf = append(buf, byte(qtype))
	buf = append(buf, 0x00, 0x01) // QCLASS=IN
	if dnssecOK {
		// EDNS0 OPT record.
		buf = append(buf, 0x00, 0x00) // NAME=root
		buf = append(buf, 0x00, 0x29) // TYPE=41 (OPT)
		buf = append(buf, 0x10, 0x00) // UDP payload size = 4096
		buf = append(buf, 0x00, 0x00) // extended RCODE + flags
		buf = append(buf, 0x00, 0x00) // RDLENGTH=0
	}
	return buf
}

func (s *DNSScanner) buildQueryWithEDNS0(name string, bufsize uint16) []byte {
	q := s.buildQuery(name, 1, false)
	// Replace ARCOUNT with 1 and append OPT.
	q[11] = 0x01
	// Append OPT record (overwrites trailing zero if present).
	q = append(q, 0x00, 0x00) // NAME=root
	q = append(q, 0x00, 0x29) // TYPE=41
	q = append(q, byte(bufsize>>8), byte(bufsize&0xFF)) // bufsize
	q = append(q, 0x00, 0x00) // extended RCODE + flags
	q = append(q, 0x00, 0x00) // RDLENGTH=0
	return q
}

func (s *DNSScanner) rawQuery(ctx context.Context, wire []byte) ([]byte, time.Duration, error) {
	addr := s.ResolverIP
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}
	conn, err := net.DialTimeout("udp", addr, s.Timeout)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(s.Timeout))
	start := time.Now()
	_, err = conn.Write(wire)
	if err != nil {
		return nil, 0, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, 0, err
	}
	return buf[:n], time.Since(start), nil
}

func (s *DNSScanner) resolveA(ctx context.Context, name string) ([]string, error) {
	resp, _, err := s.queryDNS(ctx, name, 1, false)
	if err != nil {
		return nil, err
	}
	return parseARecords(resp), nil
}

// skipDNSName advances the offset past a DNS name.
func skipDNSName(msg []byte, offset int) int {
	for offset < len(msg) {
		length := msg[offset]
		if length == 0 {
			return offset + 1
		}
		if length&0xC0 == 0xC0 {
			return offset + 2
		}
		offset += int(length) + 1
	}
	return offset
}

// parseARecords walks a DNS wire-format response and returns every A record
// (QTYPE=1) answer as a dotted-quad string. The function is duplicated here
// instead of imported from internal/networking/dns to avoid an import cycle
// (dns_battery_test lives in the diagnostics package and only needs a few
// helpers from the response decoder).
func parseARecords(resp []byte) []string {
	if len(resp) < 12 {
		return nil
	}
	qdCount := int(binary.BigEndian.Uint16(resp[4:6]))
	anCount := int(binary.BigEndian.Uint16(resp[6:8]))
	offset := 12
	// Skip the question section.
	for i := 0; i < qdCount; i++ {
		offset = skipDNSName(resp, offset)
		if offset+4 > len(resp) {
			return nil
		}
		offset += 4 // QTYPE + QCLASS
	}
	var out []string
	for i := 0; i < anCount; i++ {
		offset = skipDNSName(resp, offset)
		if offset+10 > len(resp) {
			return out
		}
		qtype := binary.BigEndian.Uint16(resp[offset : offset+2])
		// skip CLASS(2) + TTL(4)
		offset += 8
		rdlen := int(binary.BigEndian.Uint16(resp[offset : offset+2]))
		offset += 2
		if offset+rdlen > len(resp) {
			return out
		}
		if qtype == 1 && rdlen == 4 {
			ip := net.IP(resp[offset : offset+4]).String()
			out = append(out, ip)
		}
		offset += rdlen
	}
	return out
}
