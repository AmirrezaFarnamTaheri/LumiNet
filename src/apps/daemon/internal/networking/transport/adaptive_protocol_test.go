package transport

import (
	"testing"
)

func TestAdaptiveTransportCoordinator(t *testing.T) {
	coord := NewAdaptiveTransportCoordinator()

	posture := coord.AdaptAnomaly("sni_reset")
	if posture.RecommendedProtocol != "Trojan-SNI-Fragment" {
		t.Errorf("expected Trojan-SNI-Fragment for sni_reset")
	}
	if posture.WindowClampSize != 2 {
		t.Errorf("expected window clamp size 2")
	}

	posture = coord.AdaptAnomaly("udp_blackhole")
	if posture.RecommendedProtocol != "VLESS-Reality" {
		t.Errorf("expected VLESS-Reality for udp_blackhole")
	}
	if posture.ActiveBackend == EngineKcpRawSocket {
		t.Errorf("expected KCP raw socket to be demoted on UDP blackhole")
	}
}
