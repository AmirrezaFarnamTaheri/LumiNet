package proxy

import (
	"net"
	"sync"
)

type TUNFilterAction string

const (
	TUNActionAllow TUNFilterAction = "ALLOW"
	TUNActionBlock TUNFilterAction = "BLOCK"
)

type TUNPacketFilter struct {
	mu             sync.RWMutex
	blockedAddrs   map[string]bool
	IsolateClients bool
	VPNSubnet      *net.IPNet
	GatewayIP      net.IP
}

func NewTUNPacketFilter() *TUNPacketFilter {
	return &TUNPacketFilter{
		blockedAddrs:   make(map[string]bool),
		IsolateClients: true,
	}
}

func (f *TUNPacketFilter) AddRule(ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blockedAddrs[ip] = true
}

func (f *TUNPacketFilter) Evaluate(srcIP, dstIP net.IP, dstPort uint16) TUNFilterAction {
	f.mu.RLock()
	defer f.mu.RUnlock()

	// 1. Check direct blocked addresses
	if f.blockedAddrs[srcIP.String()] || f.blockedAddrs[dstIP.String()] {
		return TUNActionBlock
	}

	// 2. Lateral NetBIOS/SMB filtering (ports 137, 138, 139, 445)
	if dstPort == 137 || dstPort == 138 || dstPort == 139 || dstPort == 445 {
		return TUNActionBlock
	}

	// 3. Client-to-client IP isolation within the same VPN subnet
	if f.IsolateClients && f.VPNSubnet != nil {
		if f.VPNSubnet.Contains(srcIP) && f.VPNSubnet.Contains(dstIP) {
			// Do not block communication with the gateway/interface itself
			if !dstIP.Equal(f.GatewayIP) && !srcIP.Equal(f.GatewayIP) {
				return TUNActionBlock
			}
		}
	}

	return TUNActionAllow
}
