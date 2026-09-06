package diagnostics

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/maybeknott/luminet/internal/foundation/netpolicy"
)

// CDN candidate generation is bounded before allocation. Concurrency limits do
// not protect callers if a huge CIDR is expanded into an in-memory job list.
const (
	maxCDNRanges       = 128
	maxCDNSamplesPer24 = 16
	maxCDNCandidates   = 8192
	fullCDNHostsPer24  = 254
)

// GenerateCdnIPs parses a bounded list of IPv4 CIDRs/single IPs and returns a
// deterministic deduplicated candidate set. sampleRate is candidates per /24;
// zero requests all usable hosts but is still subject to maxCDNCandidates.
func GenerateCdnIPs(cidrs []string, sampleRate int) ([]string, error) {
	if len(cidrs) == 0 || len(cidrs) > maxCDNRanges {
		return nil, fmt.Errorf("CDN range count must be between 1 and %d", maxCDNRanges)
	}
	if sampleRate < 0 || sampleRate > maxCDNSamplesPer24 {
		return nil, fmt.Errorf("sample rate must be between 0 and %d", maxCDNSamplesPer24)
	}
	per24 := sampleRate
	if per24 == 0 {
		per24 = fullCDNHostsPer24
	}
	seen := make(map[string]struct{})
	ips := make([]string, 0, minInt(maxCDNCandidates, len(cidrs)*per24))
	appendIP := func(raw string) error {
		parsed := net.ParseIP(raw)
		if parsed == nil {
			return fmt.Errorf("invalid CDN IP %q", raw)
		}
		canonical := parsed.String()
		if _, ok := seen[canonical]; ok {
			return nil
		}
		if len(ips) >= maxCDNCandidates {
			return fmt.Errorf("CDN candidate count exceeds %d", maxCDNCandidates)
		}
		seen[canonical] = struct{}{}
		ips = append(ips, canonical)
		return nil
	}

	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return nil, fmt.Errorf("empty CDN range")
		}
		ip, network, err := net.ParseCIDR(raw)
		if err != nil {
			if err := appendIP(raw); err != nil {
				return nil, err
			}
			continue
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("CDN CIDR %q must be IPv4", raw)
		}
		ones, bits := network.Mask.Size()
		if bits != 32 || ones < 0 || ones > 32 {
			return nil, fmt.Errorf("invalid CDN CIDR %q", raw)
		}

		if ones > 24 {
			hostCount := 1 << uint(32-ones)
			if hostCount > maxCDNCandidates-len(ips) {
				return nil, fmt.Errorf("CDN CIDR %q would exceed %d candidates", raw, maxCDNCandidates)
			}
			base := binary.BigEndian.Uint32(ip4) & binary.BigEndian.Uint32(network.Mask)
			for i := 0; i < hostCount; i++ {
				if err := appendIP(valToIP(base + uint32(i))); err != nil {
					return nil, err
				}
			}
			continue
		}

		blocks := 1 << uint(24-ones)
		if blocks > maxCDNCandidates || blocks*per24 > maxCDNCandidates-len(ips) {
			return nil, fmt.Errorf("CDN CIDR %q would generate %d candidates, limit %d", raw, blocks*per24, maxCDNCandidates)
		}
		base := binary.BigEndian.Uint32(ip4) & binary.BigEndian.Uint32(network.Mask)
		for block := 0; block < blocks; block++ {
			sub := base + uint32(block*256)
			if sampleRate == 0 {
				for host := 1; host <= 254; host++ {
					if err := appendIP(valToIP(sub + uint32(host))); err != nil {
						return nil, err
					}
				}
				continue
			}
			for i := 0; i < sampleRate; i++ {
				// Evenly spaced, deterministic host offsets in [1,254].
				offset := 1
				if sampleRate > 1 {
					offset += i * 253 / (sampleRate - 1)
				}
				if err := appendIP(valToIP(sub + uint32(offset))); err != nil {
					return nil, err
				}
			}
		}
	}
	return ips, nil
}

// GeneratePublicCdnIPs applies the same deterministic bounded expansion as
// GenerateCdnIPs, then rejects any non-public candidate before active network
// work can begin. The raw generator remains available for offline fixtures and
// local planning that intentionally use documentation/private ranges.
func GeneratePublicCdnIPs(cidrs []string, sampleRate int) ([]string, error) {
	ips, err := GenerateCdnIPs(cidrs, sampleRate)
	if err != nil {
		return nil, err
	}
	public := make([]string, 0, len(ips))
	for _, raw := range ips {
		addr, err := netip.ParseAddr(raw)
		if err != nil || !netpolicy.IsPublicAddress(addr) {
			return nil, fmt.Errorf("CDN active-scan candidate %q is not a public address", raw)
		}
		public = append(public, addr.Unmap().String())
	}
	return public, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func valToIP(val uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, val)
	return ip.String()
}
