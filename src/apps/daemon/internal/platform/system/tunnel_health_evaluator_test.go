package system

import (
	"strings"
	"testing"
)

func TestEvaluateTunnelHealth(t *testing.T) {
	tests := []struct {
		name     string
		metrics  TunnelMetrics
		expected TunnelHealthVerdict
	}{
		{
			name: "Disconnected state",
			metrics: TunnelMetrics{
				PacketsTx:           0,
				PacketsRx:           0,
				LastHandshakeAgeSec: 0,
			},
			expected: VerdictDisconnected,
		},
		{
			name: "Starting state",
			metrics: TunnelMetrics{
				PacketsTx:           10,
				PacketsRx:           0,
				LastHandshakeAgeSec: 3,
				ConsecutiveFailures: 0,
			},
			expected: VerdictStarting,
		},
		{
			name: "Waiting for traffic",
			metrics: TunnelMetrics{
				PacketsTx:           10,
				PacketsRx:           0,
				LastHandshakeAgeSec: 15,
				ConsecutiveFailures: 0,
			},
			expected: VerdictWaitingForTraffic,
		},
		{
			name: "Degraded due to latency",
			metrics: TunnelMetrics{
				PacketsTx:           500,
				PacketsRx:           480,
				LatencyMs:           420,
				LossRatio:           0.02,
				LastHandshakeAgeSec: 5,
			},
			expected: VerdictDegraded,
		},
		{
			name: "Degraded due to loss",
			metrics: TunnelMetrics{
				PacketsTx:           500,
				PacketsRx:           420,
				LatencyMs:           80,
				LossRatio:           0.16,
				LastHandshakeAgeSec: 5,
			},
			expected: VerdictDegraded,
		},
		{
			name: "Reconnect needed due to high loss",
			metrics: TunnelMetrics{
				PacketsTx:           500,
				PacketsRx:           200,
				LossRatio:           0.40,
				LastHandshakeAgeSec: 10,
			},
			expected: VerdictReconnectNeeded,
		},
		{
			name: "Reconnect needed due to consecutive failures",
			metrics: TunnelMetrics{
				PacketsTx:           500,
				PacketsRx:           200,
				ConsecutiveFailures: 3,
				LastHandshakeAgeSec: 10,
			},
			expected: VerdictReconnectNeeded,
		},
		{
			name: "Broken due to 5 failures",
			metrics: TunnelMetrics{
				PacketsTx:           500,
				PacketsRx:           100,
				ConsecutiveFailures: 5,
				LastHandshakeAgeSec: 10,
			},
			expected: VerdictBroken,
		},
		{
			name: "Broken due to handshake timeout",
			metrics: TunnelMetrics{
				PacketsTx:           500,
				PacketsRx:           500,
				ConsecutiveFailures: 0,
				LastHandshakeAgeSec: 200,
			},
			expected: VerdictBroken,
		},
		{
			name: "Working healthy tunnel",
			metrics: TunnelMetrics{
				PacketsTx:           1000,
				PacketsRx:           990,
				LatencyMs:           45,
				LossRatio:           0.01,
				ConsecutiveFailures: 0,
				LastHandshakeAgeSec: 2,
			},
			expected: VerdictWorking,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := EvaluateTunnelHealth(tc.metrics)
			if res != tc.expected {
				t.Fatalf("expected verdict %s, got %s", tc.expected, res)
			}
		})
	}
}

func TestRecommendFecProfile(t *testing.T) {
	// Loss > 0.15 => Aggressive
	p1 := RecommendFecProfile(0.18, false)
	if p1.Name != "Aggressive" || p1.RedundancyPct != 40 {
		t.Fatalf("expected Aggressive FEC, got %+v", p1)
	}

	// Cellular with loss 0.09 => Aggressive
	p2 := RecommendFecProfile(0.09, true)
	if p2.Name != "Aggressive" {
		t.Fatalf("expected Aggressive FEC for cellular high loss, got %+v", p2)
	}

	// Cellular with low loss => Balanced
	p3 := RecommendFecProfile(0.02, true)
	if p3.Name != "Balanced" || p3.LossTolerancePct != 12 {
		t.Fatalf("expected Balanced FEC for cellular, got %+v", p3)
	}

	// Broadband with 0.02 loss => Conservative
	p4 := RecommendFecProfile(0.02, false)
	if p4.Name != "Conservative" || p4.FlushTimeoutMs != 25 {
		t.Fatalf("expected Conservative FEC, got %+v", p4)
	}

	// Clean connection => None
	p5 := RecommendFecProfile(0.005, false)
	if p5.Name != "None" {
		t.Fatalf("expected None FEC, got %+v", p5)
	}
}

func TestStripProfileSecrets(t *testing.T) {
	cfg := `
server = "192.168.1.1:443"
password = "supersecretpassword"
private_key = "a1b2c3d4e5f6"
preshared_key = "psk12345"
token = "bearer_abc123"
name = "MyTunnel"
`
	sanitized := StripProfileSecrets(cfg)
	if strings.Contains(sanitized, "supersecretpassword") {
		t.Fatalf("password not sanitized")
	}
	if strings.Contains(sanitized, "a1b2c3d4e5f6") {
		t.Fatalf("private_key not sanitized")
	}
	if strings.Contains(sanitized, "psk12345") {
		t.Fatalf("preshared_key not sanitized")
	}
	if strings.Contains(sanitized, "bearer_abc123") {
		t.Fatalf("token not sanitized")
	}
	if !strings.Contains(sanitized, `name = "MyTunnel"`) {
		t.Fatalf("non-secret attribute removed")
	}
}
