package proxyconfig

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// GatewayProtocol defines supported fallback protocols
type GatewayProtocol string

const (
	GatewayProtoAmneziaWG GatewayProtocol = "amnezia_wg"
	GatewayProtoVless     GatewayProtocol = "vless"
	GatewayProtoShadow22  GatewayProtocol = "shadowsocks_2022"
	GatewayProtoMasque    GatewayProtocol = "masque"
)

// ActiveGatewayEndpoint represents an orchestrated upstream tunnel endpoint
type ActiveGatewayEndpoint struct {
	EndpointID string
	Protocol   GatewayProtocol
	Address    string
	Port       uint16
	PingMs     int
	Healthy    bool
	LastTested time.Time
}

// MultiprotoProfileGateway coordinates multi-protocol ingress/egress profile dispatching
type MultiprotoProfileGateway struct {
	endpoints      map[string]*ActiveGatewayEndpoint
	primaryID      string
	failoverChain  []string
	transpiler     *OvpnConfigTranspiler
	relayAggregator *PublicRelayAggregator
	mu             sync.RWMutex
}

// NewMultiprotoProfileGateway initializes the multi-protocol profile gateway
func NewMultiprotoProfileGateway() *MultiprotoProfileGateway {
	return &MultiprotoProfileGateway{
		endpoints:       make(map[string]*ActiveGatewayEndpoint),
		transpiler:      NewOvpnConfigTranspiler(),
		relayAggregator: NewPublicRelayAggregator(),
	}
}

// RegisterEndpoint adds or updates a gateway route endpoint
func (g *MultiprotoProfileGateway) RegisterEndpoint(ep ActiveGatewayEndpoint) {
	g.mu.Lock()
	defer g.mu.Unlock()

	ep.LastTested = time.Now()
	g.endpoints[ep.EndpointID] = &ep
	if g.primaryID == "" {
		g.primaryID = ep.EndpointID
	}
}

// SetFailoverChain defines the sequence of endpoints to fallback to
func (g *MultiprotoProfileGateway) SetFailoverChain(chain []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.failoverChain = chain
	if len(chain) > 0 {
		g.primaryID = chain[0]
	}
}

// IngestPublicRelays imports discovered public relay nodes into the gateway
func (g *MultiprotoProfileGateway) IngestPublicRelays(nodes []PublicRelayNode) {
	for _, n := range nodes {
		_ = g.relayAggregator.IngestNode(n)
		var proto GatewayProtocol
		switch n.Protocol {
		case "shadowsocks":
			proto = GatewayProtoShadow22
		case "vless":
			proto = GatewayProtoVless
		case "wireguard":
			proto = GatewayProtoAmneziaWG
		default:
			proto = GatewayProtoMasque
		}

		g.RegisterEndpoint(ActiveGatewayEndpoint{
			EndpointID: n.NodeID,
			Protocol:   proto,
			Address:    n.Host,
			Port:       n.Port,
			PingMs:     n.PingMs,
			Healthy:    n.IsAlive,
		})
	}
}

// ResolveActiveRoute returns the primary healthy endpoint or steps down the failover chain
func (g *MultiprotoProfileGateway) ResolveActiveRoute() (*ActiveGatewayEndpoint, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// 1. Check primary
	if p, ok := g.endpoints[g.primaryID]; ok && p.Healthy {
		return p, nil
	}

	// 2. Check failover chain
	for _, id := range g.failoverChain {
		if ep, ok := g.endpoints[id]; ok && ep.Healthy {
			return ep, nil
		}
	}

	// 3. Fallback to any healthy endpoint
	for _, ep := range g.endpoints {
		if ep.Healthy {
			return ep, nil
		}
	}

	return nil, errors.New("no healthy gateway endpoints available")
}

// TranspileAndRegisterOvpn parses OVPN config and registers it as a gateway endpoint
func (g *MultiprotoProfileGateway) TranspileAndRegisterOvpn(endpointID string, rawOvpn string) (*ActiveGatewayEndpoint, error) {
	profile, err := g.transpiler.Transpile(rawOvpn)
	if err != nil {
		return nil, fmt.Errorf("ovpn transpilation failed: %v", err)
	}

	ep := ActiveGatewayEndpoint{
		EndpointID: endpointID,
		Protocol:   GatewayProtoAmneziaWG, // encapsulated into Amnezia/LumiNet
		Address:    profile.RemoteHost,
		Port:       profile.RemotePort,
		PingMs:     50,
		Healthy:    true,
	}

	g.RegisterEndpoint(ep)
	return &ep, nil
}
