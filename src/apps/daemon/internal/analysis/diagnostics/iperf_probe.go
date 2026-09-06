// Semantics converged from iperf3 (ESnet) rather than emulating iperf with a
// raw socket. LumiNet shells out without a command shell and consumes iperf3's
// stable JSON result contract.
package diagnostics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/netpolicy"
)

const (
	defaultIperfPort      = 5201
	defaultIperfDuration  = 5 * time.Second
	maxIperfDuration      = 60 * time.Second
	maxIperfOmit          = 10 * time.Second
	maxIperfParallel      = 16
	maxIperfUDPBitrateMbp = 1000
	maxIperfJSONBytes     = 4 << 20
)

type IperfDirectionResult struct {
	Direction     string  `json:"direction"`
	Bytes         int64   `json:"bytes"`
	Seconds       float64 `json:"seconds"`
	BandwidthMbps float64 `json:"bandwidth_mbps"`
	Retransmits   int64   `json:"retransmits,omitempty"`
	JitterMs      float64 `json:"jitter_ms,omitempty"`
	LostPackets   int64   `json:"lost_packets,omitempty"`
	Packets       int64   `json:"packets,omitempty"`
	LostPercent   float64 `json:"lost_percent,omitempty"`
}

// IperfResult retains the former aggregate fields while adding native iperf3
// direction/quality metrics. Legacy callers read the primary direction.
type IperfResult struct {
	Protocol         string                 `json:"protocol"`
	BytesTransferred int64                  `json:"bytes_transferred"`
	Duration         time.Duration          `json:"duration"`
	BandwidthMbps    float64                `json:"bandwidth_mbps"`
	Directions       []IperfDirectionResult `json:"directions"`
	CPUHostPercent   float64                `json:"cpu_host_percent,omitempty"`
	CPURemotePercent float64                `json:"cpu_remote_percent,omitempty"`
	IperfVersion     string                 `json:"iperf_version,omitempty"`
}

// IperfProbe runs the real iperf3 client protocol. The target must resolve only
// to public addresses; local/private load tests require a deliberately separate
// authorized surface rather than turning a generic diagnostic into a traffic
// generator for LAN targets.
type IperfProbe struct {
	Address        string
	Protocol       string
	Duration       time.Duration
	Omit           time.Duration
	Parallel       int
	Reverse        bool
	Bidirectional  bool
	UDPBitrateMbps int
	BinaryPath     string
}

func NewIperfProbe(addr string, proto string, duration time.Duration) *IperfProbe {
	if duration <= 0 {
		duration = defaultIperfDuration
	}
	return &IperfProbe{Address: addr, Protocol: proto, Duration: duration, Parallel: 1}
}

func (p *IperfProbe) Run(ctx context.Context) (*IperfResult, error) {
	protocol := strings.ToLower(strings.TrimSpace(p.Protocol))
	if protocol != "tcp" && protocol != "udp" {
		return nil, fmt.Errorf("iperf_probe: unsupported protocol %q", p.Protocol)
	}
	if p.Reverse && p.Bidirectional {
		return nil, errors.New("iperf_probe: reverse and bidirectional modes are mutually exclusive")
	}
	host, port, err := splitIperfAddress(p.Address)
	if err != nil {
		return nil, err
	}
	pinnedTarget, err := resolvePublicIperfTarget(ctx, host)
	if err != nil {
		return nil, err
	}

	duration := p.Duration
	if duration <= 0 {
		duration = defaultIperfDuration
	}
	if duration > maxIperfDuration {
		duration = maxIperfDuration
	}
	seconds := int(math.Ceil(duration.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	parallel := p.Parallel
	if parallel <= 0 {
		parallel = 1
	}
	if parallel > maxIperfParallel {
		parallel = maxIperfParallel
	}
	omitSeconds := int(math.Floor(p.Omit.Seconds()))
	if omitSeconds < 0 {
		omitSeconds = 0
	}
	if omitSeconds > int(maxIperfOmit.Seconds()) {
		omitSeconds = int(maxIperfOmit.Seconds())
	}
	if protocol == "udp" && (p.UDPBitrateMbps < 1 || p.UDPBitrateMbps > maxIperfUDPBitrateMbp) {
		return nil, fmt.Errorf("iperf_probe: udp_bitrate_mbps must be between 1 and %d", maxIperfUDPBitrateMbp)
	}

	binary := strings.TrimSpace(p.BinaryPath)
	if binary == "" {
		binary, err = exec.LookPath("iperf3")
		if err != nil {
			return nil, fmt.Errorf("iperf_probe: iperf3 executable unavailable: %w", err)
		}
	}
	args := []string{"-c", pinnedTarget, "-p", strconv.Itoa(port), "-J", "-t", strconv.Itoa(seconds), "-P", strconv.Itoa(parallel), "--connect-timeout", "5000"}
	if omitSeconds > 0 {
		args = append(args, "-O", strconv.Itoa(omitSeconds))
	}
	if protocol == "udp" {
		args = append(args, "-u", "-b", fmt.Sprintf("%dM", p.UDPBitrateMbps), "--udp-counters-64bit")
	}
	if p.Reverse {
		args = append(args, "-R")
	} else if p.Bidirectional {
		args = append(args, "--bidir")
	}

	cmd := exec.CommandContext(ctx, binary, args...)
	var stdout limitedBuffer
	stdout.limit = maxIperfJSONBytes
	var stderr limitedBuffer
	stderr.limit = 64 << 10
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if stdout.overflow || stderr.overflow {
			return nil, errors.New("iperf_probe: iperf3 output exceeded safety limit")
		}
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return nil, fmt.Errorf("iperf_probe: iperf3 failed: %s", message)
	}
	if stdout.overflow {
		return nil, errors.New("iperf_probe: iperf3 JSON exceeded safety limit")
	}
	return parseIperf3JSON(stdout.Bytes(), protocol, p.Reverse, p.Bidirectional)
}

type limitedBuffer struct {
	buf      bytes.Buffer
	limit    int
	overflow bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	if b.limit <= 0 || b.buf.Len() >= b.limit {
		b.overflow = true
		return original, nil
	}
	remaining := b.limit - b.buf.Len()
	if len(p) > remaining {
		_, _ = b.buf.Write(p[:remaining])
		b.overflow = true
		return original, nil
	}
	_, _ = b.buf.Write(p)
	return original, nil
}
func (b *limitedBuffer) Bytes() []byte  { return b.buf.Bytes() }
func (b *limitedBuffer) String() string { return b.buf.String() }

func splitIperfAddress(raw string) (string, int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0, errors.New("iperf_probe: address is required")
	}
	if host, portText, err := net.SplitHostPort(raw); err == nil {
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 || strings.TrimSpace(host) == "" {
			return "", 0, errors.New("iperf_probe: invalid port")
		}
		return strings.Trim(host, "[]"), port, nil
	}
	// Bare IP or DNS name defaults to iperf3's standard control port. Bare IPv6
	// literals are accepted here because no port ambiguity remains.
	if strings.ContainsAny(raw, "/?#@") {
		return "", 0, errors.New("iperf_probe: invalid host")
	}
	return strings.Trim(raw, "[]"), defaultIperfPort, nil
}

func resolvePublicIperfTarget(ctx context.Context, host string) (string, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		return selectPublicIperfAddress(host, []netip.Addr{address})
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return "", fmt.Errorf("iperf_probe: resolve target %q: %w", host, err)
	}
	return selectPublicIperfAddress(host, addresses)
}

// selectPublicIperfAddress converts DNS admission into a numeric destination.
// The iperf3 child receives this pinned address rather than the hostname so it
// cannot perform a second, post-admission DNS lookup (DNS-rebinding defense).
func selectPublicIperfAddress(host string, addresses []netip.Addr) (string, error) {
	if len(addresses) == 0 {
		return "", fmt.Errorf("iperf_probe: target %q resolved to no addresses", host)
	}
	normalized := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !netpolicy.IsPublicAddress(address) {
			return "", fmt.Errorf("iperf_probe: non-public DNS answer refused for %q: %s", host, address)
		}
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		normalized = append(normalized, address)
	}
	if len(normalized) == 0 {
		return "", fmt.Errorf("iperf_probe: target %q resolved to no usable addresses", host)
	}
	// Preserve resolver preference after validating the full answer set. This is
	// deterministic for one admission decision and avoids inventing a family
	// preference that differs from the host resolver.
	return normalized[0].String(), nil
}

type iperf3Summary struct {
	Bytes         int64   `json:"bytes"`
	Seconds       float64 `json:"seconds"`
	BitsPerSecond float64 `json:"bits_per_second"`
	Retransmits   int64   `json:"retransmits"`
	JitterMs      float64 `json:"jitter_ms"`
	LostPackets   int64   `json:"lost_packets"`
	Packets       int64   `json:"packets"`
	LostPercent   float64 `json:"lost_percent"`
}

type iperf3Document struct {
	Start struct {
		Version string `json:"version"`
	} `json:"start"`
	End struct {
		Sum                 iperf3Summary `json:"sum"`
		SumSent             iperf3Summary `json:"sum_sent"`
		SumReceived         iperf3Summary `json:"sum_received"`
		SumSentBidirReverse iperf3Summary `json:"sum_sent_bidir_reverse"`
		SumRecvBidirReverse iperf3Summary `json:"sum_received_bidir_reverse"`
		CPU                 struct {
			HostTotal   float64 `json:"host_total"`
			RemoteTotal float64 `json:"remote_total"`
		} `json:"cpu_utilization_percent"`
	} `json:"end"`
	Error string `json:"error"`
}

func parseIperf3JSON(raw []byte, protocol string, reverse, bidirectional bool) (*IperfResult, error) {
	var doc iperf3Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("iperf_probe: parse iperf3 JSON: %w", err)
	}
	if strings.TrimSpace(doc.Error) != "" {
		return nil, fmt.Errorf("iperf_probe: iperf3 reported: %s", strings.TrimSpace(doc.Error))
	}
	toDirection := func(name string, summary iperf3Summary) IperfDirectionResult {
		return IperfDirectionResult{
			Direction: name, Bytes: summary.Bytes, Seconds: summary.Seconds,
			BandwidthMbps: summary.BitsPerSecond / 1_000_000,
			Retransmits:   summary.Retransmits, JitterMs: summary.JitterMs,
			LostPackets: summary.LostPackets, Packets: summary.Packets, LostPercent: summary.LostPercent,
		}
	}
	var directions []IperfDirectionResult
	if protocol == "udp" && doc.End.Sum.Bytes > 0 {
		name := "forward"
		if reverse {
			name = "reverse"
		}
		directions = append(directions, toDirection(name, doc.End.Sum))
	} else {
		primary := doc.End.SumReceived
		if primary.Bytes == 0 {
			primary = doc.End.SumSent
		}
		name := "forward"
		if reverse {
			name = "reverse"
		}
		if primary.Bytes > 0 || primary.BitsPerSecond > 0 {
			primaryDir := toDirection(name, primary)
			primaryDir.Retransmits = doc.End.SumSent.Retransmits
			directions = append(directions, primaryDir)
		}
	}
	if bidirectional {
		reverseSummary := doc.End.SumRecvBidirReverse
		if reverseSummary.Bytes == 0 {
			reverseSummary = doc.End.SumSentBidirReverse
		}
		if reverseSummary.Bytes > 0 || reverseSummary.BitsPerSecond > 0 {
			reverseDir := toDirection("reverse", reverseSummary)
			reverseDir.Retransmits = doc.End.SumSentBidirReverse.Retransmits
			directions = append(directions, reverseDir)
		}
	}
	if len(directions) == 0 {
		return nil, errors.New("iperf_probe: iperf3 JSON contained no aggregate throughput result")
	}
	primary := directions[0]
	return &IperfResult{
		Protocol: protocol, BytesTransferred: primary.Bytes,
		Duration: time.Duration(primary.Seconds * float64(time.Second)), BandwidthMbps: primary.BandwidthMbps,
		Directions: directions, CPUHostPercent: doc.End.CPU.HostTotal, CPURemotePercent: doc.End.CPU.RemoteTotal,
		IperfVersion: doc.Start.Version,
	}, nil
}
