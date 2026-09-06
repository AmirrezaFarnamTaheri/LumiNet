package routing

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// MeshConnectionMode indicates direct UDP vs DERP relay
type MeshConnectionMode int

const (
	MeshModeDirect MeshConnectionMode = iota
	MeshModeDerpRelay
)

// MeshPeer represents a coordinated WireGuard node
type MeshPeer struct {
	PeerID           string
	PublicKey        [32]byte
	VirtualIP        net.IP
	AllowedIPs       []string
	Endpoints        []string
	DerpRegionID     uint16
	LastHandshakeTime time.Time
	IsExitNode       bool
}

// MeshWireguardCoordinator coordinates WireGuard mesh peer routing
type MeshWireguardCoordinator struct {
	mu            sync.RWMutex
	LocalPeerID   string
	LocalVirtualIP net.IP
	Peers         map[string]*MeshPeer
	DerpRelays    map[uint16]string
}

// NewMeshWireguardCoordinator constructs a new mesh coordinator
func NewMeshWireguardCoordinator(localID string, localVIP net.IP) *MeshWireguardCoordinator {
	return &MeshWireguardCoordinator{
		LocalPeerID:   localID,
		LocalVirtualIP: localVIP,
		Peers:         make(map[string]*MeshPeer),
		DerpRelays:    make(map[uint16]string),
	}
}

// RegisterDerpRelay registers a regional DERP fallback relay
func (c *MeshWireguardCoordinator) RegisterDerpRelay(regionID uint16, host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.DerpRelays[regionID] = host
}

// RegisterPeer registers or updates a peer in the mesh
func (c *MeshWireguardCoordinator) RegisterPeer(peer *MeshPeer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Peers[peer.PeerID] = peer
}

// SelectBestEndpoint selects either direct UDP or fallback relay
func (c *MeshWireguardCoordinator) SelectBestEndpoint(peerID string, now time.Time) (MeshConnectionMode, string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	peer, exists := c.Peers[peerID]
	if !exists {
		return 0, "", fmt.Errorf("peer %s not found", peerID)
	}

	if now.Sub(peer.LastHandshakeTime) < 3*time.Minute && len(peer.Endpoints) > 0 {
		return MeshModeDirect, peer.Endpoints[0], nil
	}

	if relayHost, ok := c.DerpRelays[peer.DerpRegionID]; ok {
		return MeshModeDerpRelay, relayHost, nil
	}

	if len(peer.Endpoints) > 0 {
		return MeshModeDirect, peer.Endpoints[0], nil
	}

	return 0, "", fmt.Errorf("no viable endpoint or relay for peer %s", peerID)
}

// LookupRoute finds the peer that owns or routes to the target IP
func (c *MeshWireguardCoordinator) LookupRoute(dest net.IP) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for id, peer := range c.Peers {
		if peer.VirtualIP.Equal(dest) {
			return id
		}
	}

	for id, peer := range c.Peers {
		for _, cidr := range peer.AllowedIPs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err == nil && ipNet.Contains(dest) {
				return id
			}
		}
	}

	return ""
}

// GeneratePeerConfig creates WireGuard INI config for the peer
func (c *MeshWireguardCoordinator) GeneratePeerConfig(peerID string) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	peer, exists := c.Peers[peerID]
	if !exists {
		return "", fmt.Errorf("peer %s not found", peerID)
	}

	allowed := strings.Join(peer.AllowedIPs, ", ")
	if allowed == "" {
		allowed = peer.VirtualIP.String() + "/32"
	}

	var sb strings.Builder
	sb.WriteString("[Peer]\n")
	sb.WriteString(fmt.Sprintf("PublicKey = %s\n", hex.EncodeToString(peer.PublicKey[:])))
	sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", allowed))
	if len(peer.Endpoints) > 0 {
		sb.WriteString(fmt.Sprintf("Endpoint = %s\n", peer.Endpoints[0]))
		sb.WriteString("PersistentKeepalive = 25\n")
	}

	return sb.String(), nil
}
