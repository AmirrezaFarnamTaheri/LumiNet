// Package netutil provides port registry utilities.
// (formerly package portregistry) dynamic port allocation and tracking.
// Prevents port conflicts during profile switching or standby modes.
// Ported from architectural_improvements.md recommendation.
package netutil

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// PortLease represents a leased port.
type PortLease struct {
	Port    int    `json:"port"`
	Type    string `json:"type"` // "socks5", "dns", "http", "tproxy"
	Leaser  string `json:"leaser"`
	LeasedAt time.Time `json:"leased_at"`
}

// PortRegistry manages dynamic port allocation.
type PortRegistry struct {
	mu      sync.Mutex
	leases  map[int]PortLease
	minPort int
	maxPort int
}

// NewPortRegistry creates a new port registry.
func NewPortRegistry(minPort, maxPort int) *PortRegistry {
	return &PortRegistry{
		leases:  make(map[int]PortLease),
		minPort: minPort,
		maxPort: maxPort,
	}
}

// Lease acquires a specific port.
func (r *PortRegistry) Lease(port int, leaseType, leaser string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if lease, exists := r.leases[port]; exists {
		return fmt.Errorf("port %d already leased to %s by %s", port, lease.Type, lease.Leaser)
	}

	r.leases[port] = PortLease{
		Port:     port,
		Type:     leaseType,
		Leaser:   leaser,
		LeasedAt: time.Now(),
	}
	return nil
}

// LeaseAny finds and leases an available port.
func (r *PortRegistry) LeaseAny(leaseType, leaser string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for port := r.minPort; port <= r.maxPort; port++ {
		if _, exists := r.leases[port]; !exists {
			// Verify port is actually available
			ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				continue
			}
			ln.Close()

			r.leases[port] = PortLease{
				Port:     port,
				Type:     leaseType,
				Leaser:   leaser,
				LeasedAt: time.Now(),
			}
			return port, nil
		}
	}

	return 0, fmt.Errorf("no available ports in range %d-%d", r.minPort, r.maxPort)
}

// Release releases a leased port.
func (r *PortRegistry) Release(port int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.leases, port)
}

// IsLeased checks if a port is leased.
func (r *PortRegistry) IsLeased(port int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, exists := r.leases[port]
	return exists
}

// GetLease returns the lease info for a port.
func (r *PortRegistry) GetLease(port int) (PortLease, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	lease, exists := r.leases[port]
	return lease, exists
}

// ListLeases returns all active leases.
func (r *PortRegistry) ListLeases() []PortLease {
	r.mu.Lock()
	defer r.mu.Unlock()
	leases := make([]PortLease, 0, len(r.leases))
	for _, lease := range r.leases {
		leases = append(leases, lease)
	}
	return leases
}

// ReleaseByLeaser releases all ports leased by a specific leaser.
func (r *PortRegistry) ReleaseByLeaser(leaser string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for port, lease := range r.leases {
		if lease.Leaser == leaser {
			delete(r.leases, port)
		}
	}
}

// Count returns the number of leased ports.
func (r *PortRegistry) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.leases)
}


