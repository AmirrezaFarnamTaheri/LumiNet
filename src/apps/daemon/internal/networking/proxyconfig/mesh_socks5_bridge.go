package proxyconfig

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync"
)

// Socks5RoutingDecision represents routing disposition
type Socks5RoutingDecision int

const (
	Socks5RouteDirect Socks5RoutingDecision = iota
	Socks5RouteMeshExit
	Socks5RouteBlocked
)

// MeshExitTarget represents chosen mesh exit node
type MeshExitTarget struct {
	NodeID    string
	VirtualIP net.IP
	Active    bool
}

// MeshSocks5Bridge bridges local SOCKS5 clients to mesh exit nodes
type MeshSocks5Bridge struct {
	mu          sync.RWMutex
	ListenPort  uint16
	ExitTarget  *MeshExitTarget
	Credentials map[string]string
}

// NewMeshSocks5Bridge creates a bridge instance
func NewMeshSocks5Bridge(port uint16) *MeshSocks5Bridge {
	return &MeshSocks5Bridge{
		ListenPort:  port,
		Credentials: make(map[string]string),
	}
}

// SetExitTarget assigns the mesh exit target
func (b *MeshSocks5Bridge) SetExitTarget(target *MeshExitTarget) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ExitTarget = target
}

// AddUser adds username and password authentication
func (b *MeshSocks5Bridge) AddUser(username, password string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.Credentials[username] = password
}

// Authenticate verifies user credentials
func (b *MeshSocks5Bridge) Authenticate(user, pass string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if len(b.Credentials) == 0 {
		return true
	}
	expected, ok := b.Credentials[user]
	return ok && expected == pass
}

// EvaluateRoute determines if request routes through mesh exit node
func (b *MeshSocks5Bridge) EvaluateRoute(host string, port uint16) (Socks5RoutingDecision, net.IP) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if port == 0 {
		return Socks5RouteBlocked, nil
	}

	if host == "localhost" || host == "127.0.0.1" {
		return Socks5RouteDirect, nil
	}

	if b.ExitTarget != nil && b.ExitTarget.Active {
		return Socks5RouteMeshExit, b.ExitTarget.VirtualIP
	}

	return Socks5RouteDirect, nil
}

// ParseGreeting checks SOCKS5 greeting methods
func (b *MeshSocks5Bridge) ParseGreeting(data []byte) (byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(data) < 2 {
		return 0xFF, errors.New("buffer too short")
	}
	if data[0] != 0x05 {
		return 0xFF, errors.New("invalid SOCKS version")
	}

	nmethods := int(data[1])
	if len(data) < 2+nmethods {
		return 0xFF, errors.New("incomplete methods list")
	}

	methods := data[2 : 2+nmethods]
	if len(b.Credentials) == 0 {
		if bytes.Contains(methods, []byte{0x00}) {
			return 0x00, nil // NO AUTH
		}
		return 0xFF, errors.New("client does not support NO_AUTH")
	}

	if bytes.Contains(methods, []byte{0x02}) {
		return 0x02, nil // USERNAME/PASSWORD
	}
	return 0xFF, errors.New("client does not support USER/PASSWORD AUTH")
}

// CraftReply generates SOCKS5 response packet
func (b *MeshSocks5Bridge) CraftReply(rep byte, bindIP net.IP, bindPort uint16) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(0x05)
	buf.WriteByte(rep)
	buf.WriteByte(0x00) // Reserved

	v4 := bindIP.To4()
	if v4 != nil {
		buf.WriteByte(0x01) // IPv4
		buf.Write(v4)
	} else {
		buf.WriteByte(0x04) // IPv6
		buf.Write(bindIP.To16())
	}

	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], bindPort)
	buf.Write(portBytes[:])

	return buf.Bytes()
}
