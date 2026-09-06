package routing

import (
	"testing"

	"github.com/maybeknott/luminet/internal/networking/transport"
)

func TestAdaptiveOutboundCoordinator(t *testing.T) {
	coord := NewAdaptiveOutboundResilienceCoordinator(
		OutboundPolicy{Type: PolicyDirect},
		3,
		[]byte("secret-key-1234"),
		"www.cloudflare.com",
		200,
	)

	coord.Router.AddRule("blocked.org", true, OutboundPolicy{Type: PolicyProxy, Tag: "proxy-us"})
	coord.CdnSorter.AddIP("104.16.1.1")
	coord.CdnSorter.UpdateProbeResult("104.16.1.1", 35, true)

	uid := [16]byte{0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77}
	coord.Masquerader.RegisterUser(uid)

	policy, ip, preamble := coord.RouteAndPrepareOutbound("sub.blocked.org", uid)
	if policy.Type != PolicyProxy || policy.Tag != "proxy-us" {
		t.Fatalf("expected proxy-us, got %v", policy)
	}
	if ip != "104.16.1.1" {
		t.Fatalf("expected 104.16.1.1, got %s", ip)
	}

	action := coord.HandleInboundProbe(preamble)
	if action != transport.ProbeActionAcceptStream {
		t.Fatalf("expected accept stream, got %s", action)
	}
}
