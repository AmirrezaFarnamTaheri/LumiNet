package system

import (
	"regexp"
	"strings"
)

// TunnelHealthVerdict defines the operational health state of an active VPN/tunnel.
type TunnelHealthVerdict string

const (
	VerdictDisconnected     TunnelHealthVerdict = "Disconnected"
	VerdictStarting         TunnelHealthVerdict = "Starting"
	VerdictWorking          TunnelHealthVerdict = "Working"
	VerdictDegraded         TunnelHealthVerdict = "Degraded"
	VerdictReconnectNeeded  TunnelHealthVerdict = "ReconnectNeeded"
	VerdictBroken           TunnelHealthVerdict = "Broken"
	VerdictWaitingForTraffic TunnelHealthVerdict = "WaitingForTraffic"
)

// EncryptionLevel represents tunnel cryptographic strength.
type EncryptionLevel string

const (
	EncryptionStandard EncryptionLevel = "Standard"
	EncryptionStrong   EncryptionLevel = "Strong"
	EncryptionMaximum  EncryptionLevel = "Maximum"
)

// FecProfile defines forward error correction tuning parameters for lossy links.
type FecProfile struct {
	Name             string `json:"name"`
	LossTolerancePct uint32 `json:"loss_tolerance_pct"`
	RedundancyPct    uint32 `json:"redundancy_pct"`
	FlushTimeoutMs   uint32 `json:"flush_timeout_ms"`
}

// GetFecProfile returns standard FEC profiles based on profile name.
func GetFecProfile(name string) FecProfile {
	switch strings.ToLower(name) {
	case "conservative":
		return FecProfile{
			Name:             "Conservative",
			LossTolerancePct: 8,
			RedundancyPct:    15,
			FlushTimeoutMs:   25,
		}
	case "balanced":
		return FecProfile{
			Name:             "Balanced",
			LossTolerancePct: 12,
			RedundancyPct:    25,
			FlushTimeoutMs:   20,
		}
	case "aggressive":
		return FecProfile{
			Name:             "Aggressive",
			LossTolerancePct: 16,
			RedundancyPct:    40,
			FlushTimeoutMs:   15,
		}
	default:
		return FecProfile{
			Name:             "None",
			LossTolerancePct: 0,
			RedundancyPct:    0,
			FlushTimeoutMs:   0,
		}
	}
}

// TunnelMetrics represents operational telemetry observed from packet tunnel.
type TunnelMetrics struct {
	PacketsTx           uint64  `json:"packets_tx"`
	PacketsRx           uint64  `json:"packets_rx"`
	BytesTx             uint64  `json:"bytes_tx"`
	BytesRx             uint64  `json:"bytes_rx"`
	LatencyMs           uint32  `json:"latency_ms"`
	LossRatio           float64 `json:"loss_ratio"`
	ConsecutiveFailures uint32  `json:"consecutive_failures"`
	LastHandshakeAgeSec uint64  `json:"last_handshake_age_sec"`
}

// EvaluateTunnelHealth calculates the diagnostic verdict based on network metrics.
func EvaluateTunnelHealth(m TunnelMetrics) TunnelHealthVerdict {
	if m.PacketsTx == 0 && m.PacketsRx == 0 && m.LastHandshakeAgeSec == 0 {
		return VerdictDisconnected
	}
	if m.PacketsTx > 0 && m.PacketsRx == 0 && m.LastHandshakeAgeSec < 10 && m.ConsecutiveFailures == 0 {
		return VerdictStarting
	}
	if m.ConsecutiveFailures >= 5 || m.LastHandshakeAgeSec > 180 {
		return VerdictBroken
	}
	if m.ConsecutiveFailures >= 3 || m.LastHandshakeAgeSec > 60 || m.LossRatio > 0.35 {
		return VerdictReconnectNeeded
	}
	if m.LossRatio > 0.10 || m.LatencyMs > 350 {
		return VerdictDegraded
	}
	if m.PacketsTx > 0 && m.PacketsRx == 0 && m.LastHandshakeAgeSec >= 10 {
		return VerdictWaitingForTraffic
	}
	return VerdictWorking
}

// RecommendFecProfile selects optimal FEC tuning based on observed packet loss and interface type.
func RecommendFecProfile(lossRatio float64, isCellular bool) FecProfile {
	if lossRatio > 0.15 || (isCellular && lossRatio > 0.08) {
		return GetFecProfile("aggressive")
	}
	if lossRatio > 0.05 || isCellular {
		return GetFecProfile("balanced")
	}
	if lossRatio > 0.01 {
		return GetFecProfile("conservative")
	}
	return GetFecProfile("none")
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password\s*[:=]\s*)[^\r\n,;]+`),
	regexp.MustCompile(`(?i)(private_key\s*[:=]\s*)[^\r\n,;]+`),
	regexp.MustCompile(`(?i)(preshared_key\s*[:=]\s*)[^\r\n,;]+`),
	regexp.MustCompile(`(?i)(token\s*[:=]\s*)[^\r\n,;]+`),
	regexp.MustCompile(`(?i)(secret\s*[:=]\s*)[^\r\n,;]+`),
}

// StripProfileSecrets removes passwords, private keys, and auth tokens from configuration text.
func StripProfileSecrets(rawConfig string) string {
	cleaned := rawConfig
	for _, pattern := range secretPatterns {
		cleaned = pattern.ReplaceAllString(cleaned, "${1}[REDACTED]")
	}
	return cleaned
}
