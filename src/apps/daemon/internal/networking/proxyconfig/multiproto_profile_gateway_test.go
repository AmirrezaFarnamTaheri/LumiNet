package proxyconfig

import (
	"testing"
)

func TestMultiprotoProfileGateway(t *testing.T) {
	gw := NewMultiprotoProfileGateway()

	ep1 := ActiveGatewayEndpoint{
		EndpointID: "ep-awg-primary",
		Protocol:   GatewayProtoAmneziaWG,
		Address:    "198.51.100.50",
		Port:       51820,
		PingMs:     25,
		Healthy:    true,
	}

	ep2 := ActiveGatewayEndpoint{
		EndpointID: "ep-masque-fallback",
		Protocol:   GatewayProtoMasque,
		Address:    "198.51.100.51",
		Port:       443,
		PingMs:     40,
		Healthy:    true,
	}

	gw.RegisterEndpoint(ep1)
	gw.RegisterEndpoint(ep2)
	gw.SetFailoverChain([]string{"ep-awg-primary", "ep-masque-fallback"})

	// Primary route should be ep1
	route, err := gw.ResolveActiveRoute()
	if err != nil {
		t.Fatalf("failed to resolve active route: %v", err)
	}
	if route.EndpointID != "ep-awg-primary" {
		t.Fatalf("expected ep-awg-primary, got %s", route.EndpointID)
	}

	// Mark ep1 unhealthy -> failover to ep2
	ep1.Healthy = false
	gw.RegisterEndpoint(ep1)

	route2, err := gw.ResolveActiveRoute()
	if err != nil {
		t.Fatalf("failed to resolve failover route: %v", err)
	}
	if route2.EndpointID != "ep-masque-fallback" {
		t.Fatalf("expected ep-masque-fallback after failover, got %s", route2.EndpointID)
	}

	// Test OVPN transpilation & registration
	rawOvpn := `
client
dev tun
proto udp
remote 198.51.100.99 1194
`
	ovpnEp, err := gw.TranspileAndRegisterOvpn("ep-ovpn-transpiled", rawOvpn)
	if err != nil {
		t.Fatalf("transpile and register failed: %v", err)
	}
	if ovpnEp.Address != "198.51.100.99" || ovpnEp.Port != 1194 {
		t.Fatalf("transpiled endpoint mismatch")
	}
}
