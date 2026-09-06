package proxy

import (
	"context"
	"encoding/binary"
	"net"
	"time"
)

type LatencyResult struct {
	Address string        `json:"address"`
	Latency time.Duration `json:"latency_ms"`
	Success bool          `json:"success"`
}

type NodeLatencyTester struct{}

func NewNodeLatencyTester() *NodeLatencyTester {
	return &NodeLatencyTester{}
}

func (t *NodeLatencyTester) PingTCP(ctx context.Context, addr string, timeout time.Duration) LatencyResult {
	start := time.Now()
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return LatencyResult{Address: addr, Latency: 0, Success: false}
	}
	conn.Close()
	return LatencyResult{Address: addr, Latency: time.Since(start), Success: true}
}

// PingQUIC sends a minimally-valid QUIC long-header packet with an unsupported version
// (0x0a0a0a0a - greasing version). Per RFC 9000 §6, the server MUST reply immediately
// with a Version Negotiation packet, which gives us a clean UDP round-trip latency measurement.
func (t *NodeLatencyTester) PingQUIC(ctx context.Context, addr string, timeout time.Duration) LatencyResult {
	start := time.Now()
	rAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return LatencyResult{Address: addr, Latency: 0, Success: false}
	}

	conn, err := net.DialUDP("udp", nil, rAddr)
	if err != nil {
		return LatencyResult{Address: addr, Latency: 0, Success: false}
	}
	defer conn.Close()

	// Cheap pseudo-random connection IDs from current unix nanos
	nanos := uint64(time.Now().UnixNano())
	dcid := make([]byte, 8)
	binary.LittleEndian.PutUint64(dcid, nanos)

	scid := make([]byte, 8)
	// Rotate left 17 bits equivalent
	binary.LittleEndian.PutUint64(scid, (nanos<<17)|(nanos>>47))

	// Construct QUIC Long Header packet (0xC0 = Long Header form + fixed bit)
	// 4-byte version: 0x0a0a0a0a (Greasing version)
	pkt := make([]byte, 1200)
	pkt[0] = 0xC0
	pkt[1] = 0x0a
	pkt[2] = 0x0a
	pkt[3] = 0x0a
	pkt[4] = 0x0a
	pkt[5] = byte(len(dcid))
	copy(pkt[6:14], dcid)
	pkt[14] = byte(len(scid))
	copy(pkt[15:23], scid)
	// Remaining 1200 - 23 bytes are zero-initialized

	// Set write / read deadline on UDP connection
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(pkt); err != nil {
		return LatencyResult{Address: addr, Latency: 0, Success: false}
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil || n < 5 {
		return LatencyResult{Address: addr, Latency: 0, Success: false}
	}

	return LatencyResult{Address: addr, Latency: time.Since(start), Success: true}
}

// JitterResult represents the output of a multi-sample latency and jitter measurement test.
type JitterResult struct {
	Address string        `json:"address"`
	Latency time.Duration `json:"latency_ms"`
	Jitter  time.Duration `json:"jitter_ms"`
	Success bool          `json:"success"`
}

// MeasureJitterTCP executes N sequential TCP pings and computes RTT average latency and jitter mean absolute deviation.
func (t *NodeLatencyTester) MeasureJitterTCP(ctx context.Context, addr string, samples int, interval time.Duration, timeout time.Duration) JitterResult {
	if samples <= 0 {
		return JitterResult{Address: addr, Success: false}
	}
	var latencies []time.Duration
	var total time.Duration

	for i := 0; i < samples; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return JitterResult{Address: addr, Success: false}
			case <-time.After(interval):
			}
		}
		res := t.PingTCP(ctx, addr, timeout)
		if !res.Success {
			return JitterResult{Address: addr, Success: false}
		}
		latencies = append(latencies, res.Latency)
		total += res.Latency
	}

	avg := total / time.Duration(samples)
	var sumDiff time.Duration
	for _, l := range latencies {
		diff := l - avg
		if diff < 0 {
			diff = -diff
		}
		sumDiff += diff
	}
	jitter := sumDiff / time.Duration(samples)

	return JitterResult{
		Address: addr,
		Latency: avg,
		Jitter:  jitter,
		Success: true,
	}
}

// MeasureJitterQUIC executes N sequential QUIC version-negotiation UDP pings and computes RTT average latency and jitter.
func (t *NodeLatencyTester) MeasureJitterQUIC(ctx context.Context, addr string, samples int, interval time.Duration, timeout time.Duration) JitterResult {
	if samples <= 0 {
		return JitterResult{Address: addr, Success: false}
	}
	var latencies []time.Duration
	var total time.Duration

	for i := 0; i < samples; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return JitterResult{Address: addr, Success: false}
			case <-time.After(interval):
			}
		}
		res := t.PingQUIC(ctx, addr, timeout)
		if !res.Success {
			return JitterResult{Address: addr, Success: false}
		}
		latencies = append(latencies, res.Latency)
		total += res.Latency
	}

	avg := total / time.Duration(samples)
	var sumDiff time.Duration
	for _, l := range latencies {
		diff := l - avg
		if diff < 0 {
			diff = -diff
		}
		sumDiff += diff
	}
	jitter := sumDiff / time.Duration(samples)

	return JitterResult{
		Address: addr,
		Latency: avg,
		Jitter:  jitter,
		Success: true,
	}
}

const maxEndpointQualitySamples = 32

// EndpointQualityResult is a loss-aware multi-sample quality measurement. It
// deliberately preserves partial success instead of collapsing one lost probe
// into a total failure, and uses median RTT so one slow sample cannot dominate
// endpoint selection.
type EndpointQualityResult struct {
	Address       string        `json:"address"`
	Samples       int           `json:"samples"`
	Successful    int           `json:"successful"`
	Failed        int           `json:"failed"`
	LossPercent   float64       `json:"loss_percent"`
	MedianLatency time.Duration `json:"median_latency_ms"`
	Jitter        time.Duration `json:"jitter_ms"`
	Success       bool          `json:"success"`
}

// MeasureQualityTCP performs bounded, sequential TCP reachability samples and
// returns loss, median successful RTT, and adjacent-sample jitter.
func (t *NodeLatencyTester) MeasureQualityTCP(ctx context.Context, addr string, samples int, interval, timeout time.Duration) EndpointQualityResult {
	return t.measureQuality(ctx, addr, samples, interval, func() LatencyResult {
		return t.PingTCP(ctx, addr, timeout)
	})
}

// MeasureQualityQUIC performs the same quality measurement using QUIC version
// negotiation probes.
func (t *NodeLatencyTester) MeasureQualityQUIC(ctx context.Context, addr string, samples int, interval, timeout time.Duration) EndpointQualityResult {
	return t.measureQuality(ctx, addr, samples, interval, func() LatencyResult {
		return t.PingQUIC(ctx, addr, timeout)
	})
}

func (t *NodeLatencyTester) measureQuality(ctx context.Context, addr string, samples int, interval time.Duration, ping func() LatencyResult) EndpointQualityResult {
	result := EndpointQualityResult{Address: addr}
	if samples <= 0 || samples > maxEndpointQualitySamples || interval < 0 || ping == nil {
		return result
	}
	latencies := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		if i > 0 && interval > 0 {
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				result.Samples = i
				result.Failed = i - result.Successful
				if i > 0 {
					result.LossPercent = float64(result.Failed) / float64(i) * 100
				}
				return finalizeEndpointQuality(result, latencies)
			case <-timer.C:
			}
		}
		if ctx.Err() != nil {
			result.Samples = i
			result.Failed = i - result.Successful
			return finalizeEndpointQuality(result, latencies)
		}
		probe := ping()
		result.Samples++
		if probe.Success {
			result.Successful++
			latencies = append(latencies, probe.Latency)
		} else {
			result.Failed++
		}
	}
	result.LossPercent = float64(result.Failed) / float64(result.Samples) * 100
	return finalizeEndpointQuality(result, latencies)
}

func finalizeEndpointQuality(result EndpointQualityResult, latencies []time.Duration) EndpointQualityResult {
	result.Success = len(latencies) > 0
	if len(latencies) == 0 {
		return result
	}
	ordered := append([]time.Duration(nil), latencies...)
	for i := 1; i < len(ordered); i++ {
		for j := i; j > 0 && ordered[j] < ordered[j-1]; j-- {
			ordered[j], ordered[j-1] = ordered[j-1], ordered[j]
		}
	}
	mid := len(ordered) / 2
	if len(ordered)%2 == 1 {
		result.MedianLatency = ordered[mid]
	} else {
		result.MedianLatency = (ordered[mid-1] + ordered[mid]) / 2
	}
	if len(latencies) > 1 {
		var total time.Duration
		for i := 1; i < len(latencies); i++ {
			delta := latencies[i] - latencies[i-1]
			if delta < 0 {
				delta = -delta
			}
			total += delta
		}
		result.Jitter = total / time.Duration(len(latencies)-1)
	}
	return result
}

// BetterEndpointQuality provides deterministic endpoint ordering: lower loss
// wins first, then median RTT, then jitter, then address for a stable tie-break.
func BetterEndpointQuality(a, b EndpointQualityResult) bool {
	if a.Success != b.Success {
		return a.Success
	}
	if a.LossPercent != b.LossPercent {
		return a.LossPercent < b.LossPercent
	}
	if a.MedianLatency != b.MedianLatency {
		return a.MedianLatency < b.MedianLatency
	}
	if a.Jitter != b.Jitter {
		return a.Jitter < b.Jitter
	}
	return a.Address < b.Address
}
