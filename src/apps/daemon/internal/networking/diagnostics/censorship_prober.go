package diagnostics

import (
	"fmt"
	"math"
	"net"
)

type CensorshipAnomaly string

const (
	AnomalyTcpRst       CensorshipAnomaly = "tcp_rst_injection"
	AnomalyDnsPollution CensorshipAnomaly = "dns_pollution"
	AnomalyUdpBlackhole CensorshipAnomaly = "udp_blackhole"
	AnomalySniReset     CensorshipAnomaly = "sni_reset"
)

type CensorshipSignature struct {
	Anomaly    CensorshipAnomaly
	Confidence float32
	Details    string
}

type CensorshipProber struct{}

func NewCensorshipProber() *CensorshipProber {
	return &CensorshipProber{}
}

func (p *CensorshipProber) ProbeTcpRst(synAckRcvd bool, rstRcvd bool, rstTtl uint8, synAckTtl uint8) *CensorshipSignature {
	if !rstRcvd {
		return nil
	}
	diff := math.Abs(float64(int(rstTtl) - int(synAckTtl)))
	confidence := float32(0.60)
	if diff >= 5 {
		confidence = 0.95
	} else if !synAckRcvd {
		confidence = 0.85
	}

	return &CensorshipSignature{
		Anomaly:    AnomalyTcpRst,
		Confidence: confidence,
		Details:    fmt.Sprintf("TCP RST detected with TTL delta: %.0f", diff),
	}
}

func (p *CensorshipProber) ProbeDnsPollution(domain string, ips []net.IP, knownBogus bool) *CensorshipSignature {
	if knownBogus {
		return &CensorshipSignature{
			Anomaly:    AnomalyDnsPollution,
			Confidence: 0.99,
			Details:    fmt.Sprintf("Domain %s resolved to known bogus IP", domain),
		}
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() {
			return &CensorshipSignature{
				Anomaly:    AnomalyDnsPollution,
				Confidence: 0.90,
				Details:    fmt.Sprintf("Domain %s resolved to reserved IP: %s", domain, ip.String()),
			}
		}
	}
	return nil
}

func (p *CensorshipProber) ProbeUdpDrop(sent uint32, recvd uint32) *CensorshipSignature {
	if sent < 5 {
		return nil
	}
	loss := float32(sent-recvd) / float32(sent)
	if loss >= 0.90 {
		return &CensorshipSignature{
			Anomaly:    AnomalyUdpBlackhole,
			Confidence: 0.92,
			Details:    fmt.Sprintf("High UDP loss: %.0f%%", loss*100),
		}
	}
	return nil
}
