package transport

type ProtocolPosture struct {
	RecommendedProtocol string
	ActiveBackend       BackendEngineType
	WindowClampSize     uint16
	MitigationStrategy  string
}

type AdaptiveTransportCoordinator struct {
	backendController *DualBackendController
	windowClamper     *WindowClamper
	decoyInjector     *SniDecoyInjector
}

func NewAdaptiveTransportCoordinator() *AdaptiveTransportCoordinator {
	return &AdaptiveTransportCoordinator{
		backendController: NewDualBackendController(),
		windowClamper:     NewWindowClamper(2),
		decoyInjector:     NewSniDecoyInjector("www.bing.com"),
	}
}

func (a *AdaptiveTransportCoordinator) AdaptAnomaly(anomalyType string) ProtocolPosture {
	switch anomalyType {
	case "sni_reset":
		a.windowClamper.ClampedSize = 2
		return ProtocolPosture{
			RecommendedProtocol: "Trojan-SNI-Fragment",
			ActiveBackend:       a.backendController.SelectEngine(),
			WindowClampSize:     2,
			MitigationStrategy:  "SNI record fragmentation and window clamping to 2 bytes",
		}
	case "udp_blackhole":
		a.backendController.RecordMetrics(EngineKcpRawSocket, 999, 1.0, false)
		a.backendController.RecordMetrics(EngineKcpRawSocket, 999, 1.0, false)
		a.backendController.RecordMetrics(EngineKcpRawSocket, 999, 1.0, false)
		return ProtocolPosture{
			RecommendedProtocol: "VLESS-Reality",
			ActiveBackend:       a.backendController.SelectEngine(),
			WindowClampSize:     a.windowClamper.ClampedSize,
			MitigationStrategy:  "Demoted UDP/KCP backend, forced TLS-TCP stream fallback",
		}
	case "tcp_rst_injection":
		return ProtocolPosture{
			RecommendedProtocol: "Trojan-SNI-Fragment",
			ActiveBackend:       EngineViolatedTcpQuic,
			WindowClampSize:     4,
			MitigationStrategy:  "Activated Violated TCP/QUIC engine with RST drop filter",
		}
	default:
		return ProtocolPosture{
			RecommendedProtocol: "Hysteria2",
			ActiveBackend:       a.backendController.SelectEngine(),
			WindowClampSize:     65535,
			MitigationStrategy:  "Standard baseline posture",
		}
	}
}
