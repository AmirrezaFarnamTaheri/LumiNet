
package system

import (
	"net"
	"sync"
)

// TunUDPConnAdapter maps UDP packets from a virtual TUN interface to separate UDP flows.
type TunUDPConnAdapter struct {
	mu       sync.Mutex
	conns    map[string]net.PacketConn // key -> PacketConn
	fallback net.PacketConn
	// observe, when set, receives every routed packet (src, dst,
	// payload). It must be fast and non-panicking; failures inside the
	// observer are its own responsibility. Used to attach passive
	// QUIC Initial fingerprinting (diagnostics.QuicObserverService).
	observe func(src, dst *net.UDPAddr, payload []byte)
}

// NewTunUDPConnAdapter creates a new connection adapter.
func NewTunUDPConnAdapter(fallback net.PacketConn) *TunUDPConnAdapter {
	return &TunUDPConnAdapter{
		conns:    make(map[string]net.PacketConn),
		fallback: fallback,
	}
}

// SetPacketObserver attaches a passive observation hook invoked for
// every routed packet before forwarding. Pass nil to detach.
func (a *TunUDPConnAdapter) SetPacketObserver(fn func(src, dst *net.UDPAddr, payload []byte)) {
	a.mu.Lock()
	a.observe = fn
	a.mu.Unlock()
}

// RoutePacket forwards an incoming UDP payload from TUN to the appropriate outbound UDP connection.
func (a *TunUDPConnAdapter) RoutePacket(srcAddr, dstAddr *net.UDPAddr, payload []byte) error {
	a.mu.Lock()
	observe := a.observe
	a.mu.Unlock()
	if observe != nil {
		observe(srcAddr, dstAddr, payload)
	}

	key := srcAddr.String() + "->" + dstAddr.String()

	a.mu.Lock()
	conn, ok := a.conns[key]
	if !ok {
		// Open new local outbound UDP socket
		var err error
		conn, err = net.ListenPacket("udp", "0.0.0.0:0")
		if err != nil {
			a.mu.Unlock()
			return err
		}
		a.conns[key] = conn
		a.mu.Unlock()

		// Read response loop
		go func(c net.PacketConn, src, dst *net.UDPAddr) {
			buf := make([]byte, 65536)
			for {
				n, _, err := c.ReadFrom(buf)
				if err != nil {
					break
				}
				// Route response packet back to TUN interface
				// In production, write back to TUN via the fallback connection or adapter interface
				if a.fallback != nil {
					_, _ = a.fallback.WriteTo(buf[:n], src)
				}
			}
			a.mu.Lock()
			delete(a.conns, key)
			a.mu.Unlock()
		}(conn, srcAddr, dstAddr)
	} else {
		a.mu.Unlock()
	}

	// Write payload outbound to destination
	_, err := conn.WriteTo(payload, dstAddr)
	return err
}

// Close closes all managed outbound UDP connections.
func (a *TunUDPConnAdapter) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, c := range a.conns {
		c.Close()
	}
	a.conns = make(map[string]net.PacketConn)
}
