package dns

import (
	"math"
	"sort"
	"strings"
)

// AttemptMetric captures latency and result of a single probe attempt.
type AttemptMetric struct {
	Success       bool   `json:"success"`
	DurationMs    int64  `json:"durationMs"`
	ErrorCategory string `json:"errorCategory,omitempty"`
}

// TCPProbeResult encapsulates TCP connectivity and consistency.
type TCPProbeResult struct {
	Success       bool            `json:"success"`
	Attempts      []AttemptMetric `json:"attempts"`
	MedianRTTMs   int64           `json:"medianRttMs"`
	Consistency   float64         `json:"consistency"`
	ErrorCategory string          `json:"errorCategory,omitempty"`
}

// TLSProbeResult stores TLS negotiation outcomes.
type TLSProbeResult struct {
	Success         bool     `json:"success"`
	HandshakeMs     int64    `json:"handshakeMs"`
	Version         string   `json:"version,omitempty"`
	CipherSuite     string   `json:"cipherSuite,omitempty"`
	ALPN            string   `json:"alpn,omitempty"`
	CertificateCN   string   `json:"certificateCn,omitempty"`
	CertificateSANs []string `json:"certificateSans,omitempty"`
	Verified        bool     `json:"verified"`
	ErrorCategory   string   `json:"errorCategory,omitempty"`
}

// HTTPProbeItem records individual HTTP probe requests.
type HTTPProbeItem struct {
	Method        string `json:"method"`
	URL           string `json:"url"`
	StatusCode    int    `json:"statusCode"`
	DurationMs    int64  `json:"durationMs"`
	Redirected    bool   `json:"redirected"`
	ErrorCategory string `json:"errorCategory,omitempty"`
}

// HTTPProbeResult records aggregated HTTP probing outcomes.
type HTTPProbeResult struct {
	Success bool            `json:"success"`
	Probes  []HTTPProbeItem `json:"probes"`
}

// WSProbeResult captures WebSocket handshake attempts.
type WSProbeResult struct {
	Success       bool   `json:"success"`
	StatusCode    int    `json:"statusCode"`
	DurationMs    int64  `json:"durationMs"`
	ErrorCategory string `json:"errorCategory,omitempty"`
}

// UDPProbeResult holds UDP reachability observations.
type UDPProbeResult struct {
	Reachable     bool            `json:"reachable"`
	Attempts      []AttemptMetric `json:"attempts"`
	ErrorCategory string          `json:"errorCategory,omitempty"`
}

// QUICProbeResult tracks QUIC/HTTP3 handshake status.
type QUICProbeResult struct {
	Success       bool   `json:"success"`
	HandshakeMs   int64  `json:"handshakeMs"`
	ALPN          string `json:"alpn,omitempty"`
	ErrorCategory string `json:"errorCategory,omitempty"`
}

// DNSProbeResult tracks resolver UDP/TCP answers.
type DNSProbeResult struct {
	UDPResponsive bool            `json:"udpResponsive"`
	TCPResponsive bool            `json:"tcpResponsive"`
	Answers       []string        `json:"answers,omitempty"`
	Attempts      []AttemptMetric `json:"attempts"`
	ErrorCategory string          `json:"errorCategory,omitempty"`
}

// ProbeMetrics summarizes network path latency, variance, packet loss, and stability.
type ProbeMetrics struct {
	RTTMs              int64   `json:"rttMs"`
	JitterMs           int64   `json:"jitterMs"`
	PacketLossEstimate float64 `json:"packetLossEstimate"`
	StabilityPercent   float64 `json:"stabilityPercent"`
	TimeoutFrequency   float64 `json:"timeoutFrequency"`
}

// ScoreResult details overall endpoint evaluation and middlebox classification.
type ScoreResult struct {
	Numeric        int      `json:"numeric"`
	Grade          string   `json:"grade"`
	Classification string   `json:"classification"`
	Confidence     float64  `json:"confidence"`
	FalsePositive  bool     `json:"falsePositive"`
	Reasons        []string `json:"reasons"`
}

// ComputeProbeMetrics calculates statistical metrics across probe attempts.
func ComputeProbeMetrics(tcp TCPProbeResult, udp UDPProbeResult, dns DNSProbeResult) ProbeMetrics {
	var attempts []AttemptMetric
	attempts = append(attempts, tcp.Attempts...)
	attempts = append(attempts, udp.Attempts...)
	attempts = append(attempts, dns.Attempts...)

	var successful []int64
	timeouts := 0
	for _, a := range attempts {
		if a.Success {
			successful = append(successful, a.DurationMs)
		}
		if strings.EqualFold(a.ErrorCategory, "timeout") {
			timeouts++
		}
	}

	jitter := int64(0)
	if len(successful) > 1 {
		var sum float64
		for _, v := range successful {
			sum += float64(v)
		}
		mean := sum / float64(len(successful))
		var variance float64
		for _, v := range successful {
			delta := float64(v) - mean
			variance += delta * delta
		}
		jitter = int64(math.Round(math.Sqrt(variance / float64(len(successful)))))
	}

	rtt := tcp.MedianRTTMs
	if rtt == 0 {
		rtt = medianLatency(successful)
	}

	loss := 1.0 - calculateSuccessRatio(attempts)
	timeoutFreq := 0.0
	if len(attempts) > 0 {
		timeoutFreq = float64(timeouts) / float64(len(attempts))
	}

	stability := 100.0 * (1.0 - loss)
	if jitter > 250 {
		stability -= 15
	}
	if timeoutFreq > 0.25 {
		stability -= 20
	}
	if stability < 0 {
		stability = 0
	}

	return ProbeMetrics{
		RTTMs:              rtt,
		JitterMs:           jitter,
		PacketLossEstimate: roundTwoDec(loss * 100),
		StabilityPercent:   roundTwoDec(stability),
		TimeoutFrequency:   roundTwoDec(timeoutFreq * 100),
	}
}

// ScoreProbeResult scores tunnel viability and flags middlebox spoofing.
func ScoreProbeResult(
	tcp TCPProbeResult,
	tls TLSProbeResult,
	http HTTPProbeResult,
	ws WSProbeResult,
	quic QUICProbeResult,
	dns DNSProbeResult,
	metrics ProbeMetrics,
) ScoreResult {
	points := 0
	var reasons []string

	if tcp.Success {
		points += 25
		reasons = append(reasons, "tcp_connectivity")
	}
	if tcp.Consistency >= 0.67 {
		points += 15
		reasons = append(reasons, "retry_consistency")
	}
	if tls.Success {
		points += 20
		reasons = append(reasons, "tls_handshake")
	}
	if http.Success {
		points += 8
		reasons = append(reasons, "http_behavior")
	}
	if ws.Success {
		points += 10
		reasons = append(reasons, "websocket_upgrade")
	}
	if quic.Success {
		points += 8
		reasons = append(reasons, "quic_handshake")
	}
	if dns.UDPResponsive || dns.TCPResponsive {
		points += 6
		reasons = append(reasons, "dns_responsive")
	}

	if metrics.RTTMs > 0 && metrics.RTTMs < 150 {
		points += 5
	}
	if metrics.JitterMs < 80 {
		points += 5
	}
	if metrics.StabilityPercent >= 90 {
		points += 8
	}
	if points > 100 {
		points = 100
	}

	// False positive detection:
	// Middlebox responds to TCP SYN with ACK, but drops/blocks all higher protocols,
	// or exhibits erratic consistency (< 0.67).
	falsePositive := tcp.Success && tcp.Consistency < 0.67
	if tcp.Success && !tls.Success && !http.Success && !ws.Success && !quic.Success && !dns.UDPResponsive && !dns.TCPResponsive {
		falsePositive = true
	}

	classification := "Blocked"
	switch {
	case falsePositive:
		classification = "False Positive"
	case points >= 82 && tcp.Consistency >= 0.67 && (tls.Success || ws.Success || quic.Success):
		classification = "Tunnel Ready"
	case points >= 58:
		classification = "Partially Usable"
	case points >= 38:
		classification = "Unstable"
	}

	return ScoreResult{
		Numeric:        points,
		Grade:          calculateGrade(points),
		Classification: classification,
		Confidence:     roundTwoDec(calculateConfidence(tcp, tls, http, ws, quic, metrics, falsePositive)),
		FalsePositive:  falsePositive,
		Reasons:        reasons,
	}
}

// ParseCloudflareTrace parses egress trace responses (ip, loc).
func ParseCloudflareTrace(raw string) (string, string) {
	var ip string
	var countryCode string
	for _, line := range strings.Split(raw, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "ip":
			ip = strings.TrimSpace(v)
		case "loc":
			countryCode = strings.ToUpper(strings.TrimSpace(v))
		}
	}
	return ip, countryCode
}

func calculateGrade(points int) string {
	switch {
	case points >= 94:
		return "A+"
	case points >= 85:
		return "A"
	case points >= 72:
		return "B"
	case points >= 58:
		return "C"
	case points >= 38:
		return "D"
	default:
		return "F"
	}
}

func calculateConfidence(
	tcp TCPProbeResult,
	tls TLSProbeResult,
	http HTTPProbeResult,
	ws WSProbeResult,
	quic QUICProbeResult,
	metrics ProbeMetrics,
	falsePositive bool,
) float64 {
	c := tcp.Consistency * 45
	if tls.Success {
		c += 20
	}
	if http.Success || ws.Success || quic.Success {
		c += 20
	}
	if metrics.StabilityPercent >= 85 {
		c += 15
	}
	if falsePositive {
		c -= 25
	}
	if c < 0 {
		return 0
	}
	if c > 100 {
		return 100
	}
	return c
}

func medianLatency(values []int64) int64 {
	if len(values) == 0 {
		return 0
	}
	cp := make([]int64, len(values))
	copy(cp, values)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	return cp[len(cp)/2]
}

func calculateSuccessRatio(attempts []AttemptMetric) float64 {
	if len(attempts) == 0 {
		return 0
	}
	ok := 0
	for _, a := range attempts {
		if a.Success {
			ok++
		}
	}
	return float64(ok) / float64(len(attempts))
}

func roundTwoDec(v float64) float64 {
	return math.Round(v*100) / 100
}
