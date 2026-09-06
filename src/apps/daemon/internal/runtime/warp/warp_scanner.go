// Package warp manages Cloudflare WARP integrations, configurations, and scanning pipelines.
//
// The scanner keeps endpoint generation, bounded concurrency, repeated quality
// measurement, and ranking separate from the WireGuard handshake primitive.
// Earlier LumiNet versions carried a Loss field but only performed one attempt;
// the converged scanner now derives loss from bounded repeated handshakes and
// ranks stable endpoints ahead of merely fast ones.
package warp

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultWarpAttempts   = 3
	maxWarpAttempts       = 9
	maxWarpConcurrency    = 128
	maxWarpCandidates     = 4096
	MaxWarpNoisePackets   = 64
	maxWarpNetworkTimeout = 30 * time.Second
)

var defaultWarpTestPorts = []uint16{
	500, 854, 859, 864, 878, 880, 890, 891, 894, 903,
	908, 928, 934, 939, 942, 943, 945, 946, 955, 968,
	987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387,
	1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177,
	4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559,
	8319, 8742, 8854, 8886,
}

var defaultWarpIPv4Prefixes = []string{
	"188.114.96.", "188.114.97.", "188.114.98.", "188.114.99.",
	"162.159.192.", "162.159.193.", "162.159.195.",
	"8.34.146.", "8.39.214.", "8.39.204.", "8.6.112.",
	"8.35.211.", "8.39.125.", "8.47.69.",
}

var defaultWarpIPv6Prefixes = []string{
	"2606:4700:d0::", "2606:4700:d1::",
}

// WarpScanResult holds the result of scanning a WARP endpoint.
type WarpScanResult struct {
	AddrPort           netip.AddrPort `json:"addr_port"`
	RTT                time.Duration  `json:"rtt"`
	Jitter             time.Duration  `json:"jitter"`
	Loss               float64        `json:"loss"`
	Attempts           int            `json:"attempts"`
	SuccessfulAttempts int            `json:"successful_attempts"`
	Success            bool           `json:"success"`
	Error              string         `json:"error,omitempty"`
}

// WarpScannerOptions controls the scan pipeline.
type WarpScannerOptions struct {
	ConcurrentScanners  int
	ConnectionTimeout   time.Duration
	HandshakeTimeout    time.Duration
	StopOnFirstGoodIPs  int
	Ipv4Mode            bool
	Ipv6Mode            bool
	UseNoise            bool
	NoiseCount          int
	TestPorts           []uint16
	AttemptsPerEndpoint int
	AttemptStagger      time.Duration
	WarpPrivateKey      string
	WarpPeerPublicKey   string
	WarpPresharedKey    string
}

// ValidateScanLimits rejects API-sized requests that would otherwise be silently
// normalized by NewWarpScanner. Internal callers remain safely clamped, while
// operator-facing callers can distinguish an invalid request from an accepted one.
func ValidateScanLimits(candidateCount, concurrency int, timeout time.Duration, attempts, noiseCount int) error {
	if candidateCount < 0 || candidateCount > maxWarpCandidates {
		return fmt.Errorf("candidate count must be between 0 and %d", maxWarpCandidates)
	}
	if concurrency < 0 || concurrency > maxWarpConcurrency {
		return fmt.Errorf("concurrency must be between 0 and %d", maxWarpConcurrency)
	}
	if timeout < 0 || timeout > maxWarpNetworkTimeout {
		return fmt.Errorf("timeout must be between 0 and %s", maxWarpNetworkTimeout)
	}
	if attempts < 0 || attempts > maxWarpAttempts {
		return fmt.Errorf("attempts must be between 0 and %d", maxWarpAttempts)
	}
	return ValidateNoiseCount(noiseCount)
}

// ValidateNoiseCount bounds standalone and scanner-owned noise emission before
// any network resource is created.
func ValidateNoiseCount(count int) error {
	if count < 0 || count > MaxWarpNoisePackets {
		return fmt.Errorf("noise count must be between 0 and %d", MaxWarpNoisePackets)
	}
	return nil
}

type warpEndpointProbe func(context.Context, netip.AddrPort) (time.Duration, error)

// WarpScanner manages endpoint check operations.
type WarpScanner struct {
	opts  WarpScannerOptions
	probe warpEndpointProbe
}

// NewWarpScanner creates a new WarpScanner instance.
func NewWarpScanner(opts WarpScannerOptions) *WarpScanner {
	if opts.ConcurrentScanners <= 0 {
		opts.ConcurrentScanners = 20
	}
	if opts.ConcurrentScanners > maxWarpConcurrency {
		opts.ConcurrentScanners = maxWarpConcurrency
	}
	if opts.ConnectionTimeout <= 0 {
		opts.ConnectionTimeout = 2 * time.Second
	}
	if opts.ConnectionTimeout > maxWarpNetworkTimeout {
		opts.ConnectionTimeout = maxWarpNetworkTimeout
	}
	if opts.HandshakeTimeout <= 0 {
		opts.HandshakeTimeout = 3 * time.Second
	}
	if opts.HandshakeTimeout > maxWarpNetworkTimeout {
		opts.HandshakeTimeout = maxWarpNetworkTimeout
	}
	if opts.NoiseCount < 0 {
		opts.NoiseCount = 0
	}
	if opts.NoiseCount > MaxWarpNoisePackets {
		opts.NoiseCount = MaxWarpNoisePackets
	}
	if len(opts.TestPorts) == 0 {
		opts.TestPorts = append([]uint16(nil), defaultWarpTestPorts...)
	} else {
		opts.TestPorts = append([]uint16(nil), opts.TestPorts...)
	}
	if opts.AttemptsPerEndpoint <= 0 {
		opts.AttemptsPerEndpoint = defaultWarpAttempts
	}
	if opts.AttemptsPerEndpoint > maxWarpAttempts {
		opts.AttemptsPerEndpoint = maxWarpAttempts
	}
	if opts.AttemptStagger < 0 {
		opts.AttemptStagger = 0
	}
	if opts.AttemptStagger == 0 {
		opts.AttemptStagger = 20 * time.Millisecond
	}
	if opts.WarpPeerPublicKey == "" {
		opts.WarpPeerPublicKey = CloudflareWarpPublicKey
	}

	ws := &WarpScanner{opts: opts}
	ws.probe = func(ctx context.Context, addr netip.AddrPort) (time.Duration, error) {
		return pingWarpHandshake(ctx, addr, ws.opts)
	}
	return ws
}

// GenerateCandidates generates unique randomized Cloudflare WARP endpoint
// candidates from the scanner's authoritative address and port corpus.
func (ws *WarpScanner) GenerateCandidates(count int) []netip.AddrPort {
	if count <= 0 {
		return nil
	}
	if count > maxWarpCandidates {
		count = maxWarpCandidates
	}

	seen := make(map[netip.AddrPort]struct{}, count)
	candidates := make([]netip.AddrPort, 0, count)

	ipv4Count := count
	ipv6Count := 0
	if ws.opts.Ipv4Mode && ws.opts.Ipv6Mode {
		ipv4Count = count / 2
		ipv6Count = count - ipv4Count
	} else if ws.opts.Ipv6Mode && !ws.opts.Ipv4Mode {
		ipv4Count = 0
		ipv6Count = count
	}

	for len(candidates) < ipv4Count {
		prefix := defaultWarpIPv4Prefixes[rand.IntN(len(defaultWarpIPv4Prefixes))]
		ip, err := netip.ParseAddr(fmt.Sprintf("%s%d", prefix, rand.IntN(256)))
		if err != nil {
			continue
		}
		candidate := netip.AddrPortFrom(ip, ws.opts.TestPorts[rand.IntN(len(ws.opts.TestPorts))])
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		candidates = append(candidates, candidate)
	}

	for len(candidates) < ipv4Count+ipv6Count {
		prefix := defaultWarpIPv6Prefixes[rand.IntN(len(defaultWarpIPv6Prefixes))]
		ipStr := fmt.Sprintf("%s%x:%x:%x:%x", prefix,
			rand.IntN(65536), rand.IntN(65536), rand.IntN(65536), rand.IntN(65536))
		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue
		}
		candidate := netip.AddrPortFrom(ip, ws.opts.TestPorts[rand.IntN(len(ws.opts.TestPorts))])
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		candidates = append(candidates, candidate)
	}

	return candidates
}

// Scan runs the pipeline over a set of target addresses.
func (ws *WarpScanner) Scan(ctx context.Context, candidates []netip.AddrPort) []WarpScanResult {
	if len(candidates) == 0 {
		return nil
	}

	var masterWG sync.WaitGroup
	var successfulScans atomic.Int32
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	inChan := make(chan netip.AddrPort, len(candidates))
	for _, candidate := range candidates {
		inChan <- candidate
	}
	close(inChan)

	outChan := make(chan WarpScanResult, len(candidates))
	concurrency := ws.opts.ConcurrentScanners
	if concurrency > len(candidates) {
		concurrency = len(candidates)
	}

	for i := 0; i < concurrency; i++ {
		masterWG.Add(1)
		go func() {
			defer masterWG.Done()
			for addr := range inChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				result := ws.checkEndpoint(ctx, addr)
				outChan <- result
				if result.Success && result.Loss == 0 && ws.opts.StopOnFirstGoodIPs > 0 && successfulScans.Add(1) >= int32(ws.opts.StopOnFirstGoodIPs) {
					cancel()
					return
				}
			}
		}()
	}

	masterWG.Wait()
	close(outChan)

	results := make([]WarpScanResult, 0, len(candidates))
	for result := range outChan {
		results = append(results, result)
	}

	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Success != results[j].Success {
			return results[i].Success
		}
		if results[i].Loss != results[j].Loss {
			return results[i].Loss < results[j].Loss
		}
		if results[i].Jitter != results[j].Jitter {
			return results[i].Jitter < results[j].Jitter
		}
		return results[i].RTT < results[j].RTT
	})
	return results
}

type warpAttempt struct {
	rtt time.Duration
	err error
}

func (ws *WarpScanner) checkEndpoint(ctx context.Context, addr netip.AddrPort) WarpScanResult {
	attempts := make([]warpAttempt, 0, ws.opts.AttemptsPerEndpoint)
	for i := 0; i < ws.opts.AttemptsPerEndpoint; i++ {
		if i > 0 && ws.opts.AttemptStagger > 0 {
			timer := time.NewTimer(ws.opts.AttemptStagger)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				attempts = append(attempts, warpAttempt{err: ctx.Err()})
				return summarizeWarpAttempts(addr, attempts)
			case <-timer.C:
			}
		}

		rtt, err := ws.probe(ctx, addr)
		attempts = append(attempts, warpAttempt{rtt: rtt, err: err})
		if errors.Is(err, context.Canceled) || (errors.Is(err, context.DeadlineExceeded) && ctx.Err() != nil) {
			break
		}
	}
	return summarizeWarpAttempts(addr, attempts)
}

func summarizeWarpAttempts(addr netip.AddrPort, attempts []warpAttempt) WarpScanResult {
	result := WarpScanResult{AddrPort: addr, Attempts: len(attempts)}
	if len(attempts) == 0 {
		result.Loss = 100
		result.Error = "endpoint was not probed"
		return result
	}

	successfulRTTs := make([]time.Duration, 0, len(attempts))
	var lastErr error
	for _, attempt := range attempts {
		if attempt.err != nil {
			lastErr = attempt.err
			continue
		}
		successfulRTTs = append(successfulRTTs, attempt.rtt)
	}

	result.SuccessfulAttempts = len(successfulRTTs)
	result.Loss = float64(len(attempts)-len(successfulRTTs)) / float64(len(attempts)) * 100
	if len(successfulRTTs) == 0 {
		if lastErr != nil {
			result.Error = fmt.Sprintf("all %d attempts failed: %v", len(attempts), lastErr)
		} else {
			result.Error = fmt.Sprintf("all %d attempts failed", len(attempts))
		}
		return result
	}

	result.Jitter = meanAbsoluteRTTDelta(successfulRTTs)
	sort.Slice(successfulRTTs, func(i, j int) bool { return successfulRTTs[i] < successfulRTTs[j] })
	result.Success = true
	result.RTT = successfulRTTs[len(successfulRTTs)/2]
	return result
}

func meanAbsoluteRTTDelta(samples []time.Duration) time.Duration {
	if len(samples) < 2 {
		return 0
	}
	var total time.Duration
	for i := 1; i < len(samples); i++ {
		delta := samples[i] - samples[i-1]
		if delta < 0 {
			delta = -delta
		}
		total += delta
	}
	return total / time.Duration(len(samples)-1)
}

// IcmpPing performs an ICMP ping.
func IcmpPing(ctx context.Context, ip string, timeout time.Duration) (time.Duration, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0, errors.New("invalid IP")
	}

	var network string
	if parsed.To4() != nil {
		network = "ip4:icmp"
	} else {
		network = "ip6:ipv6-icmp"
	}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, network, ip)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	var msgType byte
	if parsed.To4() != nil {
		msgType = 8
	} else {
		msgType = 128
	}

	id := os.Getpid() & 0xffff
	seq := 1

	msg := make([]byte, 8)
	msg[0] = msgType
	msg[4] = byte(id >> 8)
	msg[5] = byte(id & 0xff)
	msg[6] = byte(seq >> 8)
	msg[7] = byte(seq & 0xff)

	sum := uint32(0)
	for i := 0; i+1 < len(msg); i += 2 {
		sum += uint32(msg[i])<<8 | uint32(msg[i+1])
	}
	for sum>>16 > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	checksum := uint16(^sum)
	msg[2] = byte(checksum >> 8)
	msg[3] = byte(checksum & 0xff)

	t0 := time.Now()
	if _, err := conn.Write(msg); err != nil {
		return 0, err
	}

	reply := make([]byte, 128)
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	if _, err := conn.Read(reply); err != nil {
		return 0, err
	}
	return time.Since(t0), nil
}
