// Package scanner provides network and DNS probing tools.
// Structural cleanroom implementation conforming to §8 rules.

package scanner

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Standard RFC 5737 TEST-NET documentation addresses
var RFC5737TestNetIPs = []string{
	"192.0.2.1",   // TEST-NET-1
	"198.51.100.1", // TEST-NET-2
	"203.0.113.1",  // TEST-NET-3
}

// TunnelProberConfig configures the tunnel and transparent proxy prober.
type TunnelProberConfig struct {
	Timeout          time.Duration `json:"timeout"`
	Workers          int           `json:"workers"`
	EDNS0BufferSize  uint16        `json:"edns0_buffer_size"`
	ScoreThreshold   int           `json:"score_threshold"`
	TestNearbySubnet bool          `json:"test_nearby_subnet"`
}

// DefaultTunnelProberConfig returns conservative production defaults.
func DefaultTunnelProberConfig() TunnelProberConfig {
	return TunnelProberConfig{
		Timeout:          3 * time.Second,
		Workers:          8,
		EDNS0BufferSize:  1232,
		ScoreThreshold:   3,
		TestNearbySubnet: false,
	}
}

// TunnelStageResult records the outcome of individual tunnel capability probes.
type TunnelStageResult struct {
	NsOk           bool          `json:"ns_ok"`
	TxtOk          bool          `json:"txt_ok"`
	RandomSubOk    bool          `json:"random_sub_ok"`
	TunnelRealism  bool          `json:"tunnel_realism"`
	Edns0Supported bool          `json:"edns0_supported"`
	NxdomainRatio  float64       `json:"nxdomain_ratio"`
	Latency        time.Duration `json:"latency"`
	TotalScore     int           `json:"total_score"`
	Qualified      bool          `json:"qualified"`
	TransparentDPI bool          `json:"transparent_dpi"`
	Error          string        `json:"error,omitempty"`
}

// ComputeTunnelScore calculates composite score [0..6] for a DNS resolver.
func ComputeTunnelScore(r *TunnelStageResult) int {
	score := 0
	if r.NsOk {
		score++
	}
	if r.TxtOk {
		score++
	}
	if r.RandomSubOk {
		score++
	}
	if r.TunnelRealism {
		score++
	}
	if r.Edns0Supported {
		score++
	}
	if r.NxdomainRatio >= 0.75 {
		score++
	}
	return score
}

// FormatTunnelRealismQName generates an RFC 4648 Base32 57-char label representing dnstt payload envelope.
func FormatTunnelRealismQName(tunnelDomain string) string {
	raw := make([]byte, 36) // 36 bytes * 8 / 5 = 57.6 chars => 58 chars, truncated to 57
	_, _ = rand.Read(raw)
	encoded := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
	if len(encoded) > 57 {
		encoded = encoded[:57]
	}
	cleanDomain := strings.Trim(tunnelDomain, ".")
	return fmt.Sprintf("%s.%s.", encoded, cleanDomain)
}

// DetectTransparentProxy probes RFC 5737 documentation IPs.
// If any documentation IP responds to DNS queries on UDP 53, local ISP enforces transparent DNS hijacking.
func DetectTransparentProxy(ctx context.Context, timeout time.Duration) (bool, string, error) {
	for _, docIP := range RFC5737TestNetIPs {
		resp, err := queryDNSDirect(ctx, docIP, 53, "example.com.", dns.TypeA, timeout, 512)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			return true, docIP, nil
		}
	}
	return false, "", nil
}

// EvaluateTunnelCapability performs full 6-stage probing of a target resolver.
func EvaluateTunnelCapability(ctx context.Context, resolverIP string, port int, tunnelDomain string, cfg TunnelProberConfig) TunnelStageResult {
	if port <= 0 {
		port = 53
	}
	res := TunnelStageResult{}
	start := time.Now()

	// 1. NS check
	nsMsg, err := queryDNSDirect(ctx, resolverIP, port, tunnelDomain, dns.TypeNS, cfg.Timeout, cfg.EDNS0BufferSize)
	if err == nil && nsMsg != nil && (nsMsg.Rcode == dns.RcodeSuccess || nsMsg.Rcode == dns.RcodeNameError) {
		res.NsOk = true
	}

	// 2. TXT check
	txtMsg, err := queryDNSDirect(ctx, resolverIP, port, tunnelDomain, dns.TypeTXT, cfg.Timeout, cfg.EDNS0BufferSize)
	if err == nil && txtMsg != nil && (txtMsg.Rcode == dns.RcodeSuccess || txtMsg.Rcode == dns.RcodeNameError) {
		res.TxtOk = true
	}

	// 3. Random Subdomain check
	randSub := fmt.Sprintf("probe-%x.%s", time.Now().UnixNano()%0xFFFFFF, strings.Trim(tunnelDomain, "."))
	subMsg, err := queryDNSDirect(ctx, resolverIP, port, randSub, dns.TypeA, cfg.Timeout, cfg.EDNS0BufferSize)
	if err == nil && subMsg != nil && (subMsg.Rcode == dns.RcodeSuccess || subMsg.Rcode == dns.RcodeNameError) {
		res.RandomSubOk = true
	}

	// 4. Tunnel Realism check (57-char Base32 label)
	realismQName := FormatTunnelRealismQName(tunnelDomain)
	realMsg, err := queryDNSDirect(ctx, resolverIP, port, realismQName, dns.TypeTXT, cfg.Timeout, cfg.EDNS0BufferSize)
	if err == nil && realMsg != nil && (realMsg.Rcode == dns.RcodeSuccess || realMsg.Rcode == dns.RcodeNameError) {
		res.TunnelRealism = true
	}

	// 5. EDNS0 Support check
	if realMsg != nil && realMsg.IsEdns0() != nil {
		res.Edns0Supported = true
	} else if txtMsg != nil && txtMsg.IsEdns0() != nil {
		res.Edns0Supported = true
	}

	// 6. NXDOMAIN Ratio check across 4 non-existent domains
	nxCount := 0
	sampleTotal := 4
	for i := 0; i < sampleTotal; i++ {
		fakeQName := fmt.Sprintf("nonexistent-%x-%d.invalid.", time.Now().UnixNano(), i)
		nxMsg, qErr := queryDNSDirect(ctx, resolverIP, port, fakeQName, dns.TypeA, cfg.Timeout, cfg.EDNS0BufferSize)
		if qErr == nil && nxMsg != nil && nxMsg.Rcode == dns.RcodeNameError {
			nxCount++
		}
	}
	res.NxdomainRatio = float64(nxCount) / float64(sampleTotal)
	res.Latency = time.Since(start)
	res.TotalScore = ComputeTunnelScore(&res)
	res.Qualified = res.TotalScore >= cfg.ScoreThreshold

	return res
}

// GenerateNearbyIPs generates neighbor IPv4 addresses around a responsive target within its /24.
// It avoids network (0) and broadcast (255) addresses and skips the center IP itself.
func GenerateNearbyIPs(center netip.Addr, offsets []int) []netip.Addr {
	if !center.Is4() {
		return nil
	}
	if len(offsets) == 0 {
		offsets = []int{-16, -8, -4, -2, -1, 1, 2, 4, 8, 16}
	}

	octets := center.As4()
	baseHost := int(octets[3])
	seen := make(map[netip.Addr]bool)
	var result []netip.Addr

	for _, offset := range offsets {
		targetHost := baseHost + offset
		if targetHost > 0 && targetHost < 255 && targetHost != baseHost {
			candidate := netip.AddrFrom4([4]byte{octets[0], octets[1], octets[2], byte(targetHost)})
			if !seen[candidate] {
				seen[candidate] = true
				result = append(result, candidate)
			}
		}
	}
	return result
}

// BatchScanNearby scans candidate neighboring IPs concurrently.
func BatchScanNearby(ctx context.Context, center netip.Addr, port int, tunnelDomain string, cfg TunnelProberConfig) map[netip.Addr]TunnelStageResult {
	candidates := GenerateNearbyIPs(center, nil)
	results := make(map[netip.Addr]TunnelStageResult)
	var mu sync.Mutex

	sem := make(chan struct{}, cfg.Workers)
	var wg sync.WaitGroup

	for _, ip := range candidates {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(target netip.Addr) {
			defer wg.Done()
			defer func() { <-sem }()

			eval := EvaluateTunnelCapability(ctx, target.String(), port, tunnelDomain, cfg)
			mu.Lock()
			results[target] = eval
			mu.Unlock()
		}(ip)
	}

	wg.Wait()
	return results
}

// queryDNSDirect is a low-level UDP DNS query exchange with EDNS0 opt-in.
func queryDNSDirect(ctx context.Context, resolver string, port int, name string, qtype uint16, timeout time.Duration, ednsSize uint16) (*dns.Msg, error) {
	if !strings.HasSuffix(name, ".") {
		name = name + "."
	}
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = true
	if ednsSize > 0 {
		m.SetEdns0(ednsSize, false)
	}

	c := &dns.Client{
		Net:     "udp",
		Timeout: timeout,
	}

	addr := net.JoinHostPort(resolver, fmt.Sprintf("%d", port))
	resp, _, err := c.ExchangeContext(ctx, m, addr)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("empty dns response")
	}
	return resp, nil
}
