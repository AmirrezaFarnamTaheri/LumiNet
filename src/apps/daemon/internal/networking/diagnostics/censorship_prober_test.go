package diagnostics

import (
	"net"
	"testing"
)

func TestCensorshipProber(t *testing.T) {
	prober := NewCensorshipProber()

	// TCP RST probe with large TTL difference
	sig := prober.ProbeTcpRst(true, true, 48, 56)
	if sig == nil || sig.Anomaly != AnomalyTcpRst || sig.Confidence < 0.9 {
		t.Errorf("failed TCP RST anomaly detection")
	}

	// DNS probe with loopback IP
	dnsSig := prober.ProbeDnsPollution("twitter.com", []net.IP{net.ParseIP("127.0.0.1")}, false)
	if dnsSig == nil || dnsSig.Anomaly != AnomalyDnsPollution {
		t.Errorf("failed DNS pollution detection")
	}

	// UDP probe with 100% loss
	udpSig := prober.ProbeUdpDrop(10, 0)
	if udpSig == nil || udpSig.Anomaly != AnomalyUdpBlackhole {
		t.Errorf("failed UDP blackhole detection")
	}
}
