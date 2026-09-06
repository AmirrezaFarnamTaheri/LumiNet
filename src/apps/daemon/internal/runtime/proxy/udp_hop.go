package proxy

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// UDPHopConn — a net.PacketConn that periodically changes its local UDP port
// and randomly selects a new remote address from a pool.
//
// This defeats stateful UDP flow tracking by GFW/middleboxes because each
// hop opens a new UDP socket on a new source port and (optionally) a new
// destination port within a configured range.
//
// Design (identical to Hysteria2's udphop):
//   - prevConn:    old socket, still reading (overlap window prevents packet loss)
//   - currentConn: new socket, all writes go here
//   - After the next hop: prevConn is closed, currentConn becomes prevConn
//   - recvLoop runs concurrently on both conns; all received packets go to recvQueue
//
// Source: hysteria-master/extras/transport/udphop/conn.go
// ─────────────────────────────────────────────────────────────────────────────

const (
	udpHopPacketQueueSize = 1024
	udpHopBufferSize      = 2048 // QUIC/UDP packets ≤ 1500 bytes
	udpHopDefaultInterval = 30 * time.Second
	udpHopMinInterval     = 5 * time.Second
)

// HopIntervalConfig specifies the random range for hop timing.
type HopIntervalConfig struct {
	Min time.Duration
	Max time.Duration
}

// Normalize validates and fills defaults for HopIntervalConfig.
func (h HopIntervalConfig) Normalize() (HopIntervalConfig, error) {
	if h.Min == 0 && h.Max == 0 {
		return HopIntervalConfig{Min: udpHopDefaultInterval, Max: udpHopDefaultInterval}, nil
	}
	if h.Min == 0 || h.Max == 0 {
		return HopIntervalConfig{}, errors.New("udp_hop: both min and max must be set")
	}
	if h.Min > h.Max {
		return HopIntervalConfig{}, errors.New("udp_hop: min must not be greater than max")
	}
	if h.Min < udpHopMinInterval {
		return HopIntervalConfig{}, fmt.Errorf("udp_hop: hop interval must be at least %s", udpHopMinInterval)
	}
	return h, nil
}

// udpHopPacket is a received UDP packet held in the receive queue.
type udpHopPacket struct {
	buf  []byte
	n    int
	addr net.Addr
	err  error
}

// UDPHopConn implements net.PacketConn with automatic UDP port hopping.
// It is safe for concurrent use from multiple goroutines.
type UDPHopConn struct {
	remoteAddrs []net.UDPAddr
	hopInterval HopIntervalConfig
	listenFn    func() (net.PacketConn, error)

	mu          sync.RWMutex
	prevConn    net.PacketConn
	currentConn net.PacketConn
	addrIndex   int

	readBufSize   int
	writeBufSize  int
	deadline      time.Time
	readDeadline  time.Time
	writeDeadline time.Time

	recvQueue chan *udpHopPacket
	closeChan chan struct{}
	closed    bool

	bufPool sync.Pool
	rng     *rand.Rand
}

// NewUDPHopConn creates a new hopping UDP connection to the given addresses.
// remoteAddrs must have at least one entry; multiple entries allow random address selection.
// listenFn is called to open a new UDP socket on each hop (nil = net.ListenUDP("udp", nil)).
func NewUDPHopConn(remoteAddrs []net.UDPAddr, hopInterval HopIntervalConfig, listenFn func() (net.PacketConn, error)) (*UDPHopConn, error) {
	if len(remoteAddrs) == 0 {
		return nil, errors.New("udp_hop: at least one remote address required")
	}
	hopInterval, err := hopInterval.Normalize()
	if err != nil {
		return nil, err
	}
	if listenFn == nil {
		listenFn = func() (net.PacketConn, error) {
			return net.ListenUDP("udp", nil)
		}
	}

	curConn, err := listenFn()
	if err != nil {
		return nil, fmt.Errorf("udp_hop: initial listen: %w", err)
	}

	//nolint:gosec // not used for crypto
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	c := &UDPHopConn{
		remoteAddrs: remoteAddrs,
		hopInterval: hopInterval,
		listenFn:    listenFn,
		currentConn: curConn,
		addrIndex:   rng.Intn(len(remoteAddrs)),
		recvQueue:   make(chan *udpHopPacket, udpHopPacketQueueSize),
		closeChan:   make(chan struct{}),
		rng:         rng,
		bufPool: sync.Pool{
			New: func() interface{} {
				b := make([]byte, udpHopBufferSize)
				return &b
			},
		},
	}

	go c.recvLoop(curConn)
	go c.hopLoop()
	return c, nil
}

// LocalAddr returns the current local UDP address.
func (c *UDPHopConn) LocalAddr() net.Addr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentConn.LocalAddr()
}

// RemoteAddr returns the currently selected remote address.
func (c *UDPHopConn) RemoteAddr() *net.UDPAddr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return &c.remoteAddrs[c.addrIndex]
}

// WriteTo sends b to the currently selected remote address (addr is ignored).
// To send to the hopping remote addr, use Write() or pass the address from RemoteAddr().
func (c *UDPHopConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	return c.currentConn.WriteTo(b, &c.remoteAddrs[c.addrIndex])
}

// Write sends b to the currently selected remote address.
func (c *UDPHopConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, nil)
}

// ReadFrom reads the next packet from the receive queue.
func (c *UDPHopConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		select {
		case pkt := <-c.recvQueue:
			if pkt.err != nil {
				// Timeout errors pass through; permanent errors cause return
				if ne, ok := pkt.err.(net.Error); ok && ne.Timeout() {
					return 0, nil, pkt.err
				}
				continue
			}
			n := copy(b, pkt.buf[:pkt.n])
			addr := pkt.addr
			// Return buffer to pool
			buf := pkt.buf
			c.bufPool.Put(&buf)
			// Always report sender as the configured remote addr for simplicity
			if addr == nil {
				addr = &c.remoteAddrs[c.addrIndex]
			}
			return n, addr, nil
		case <-c.closeChan:
			return 0, nil, net.ErrClosed
		}
	}
}

// Close shuts down the connection and all goroutines.
func (c *UDPHopConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	close(c.closeChan)
	if c.prevConn != nil {
		_ = c.prevConn.Close()
	}
	err := c.currentConn.Close()
	c.remoteAddrs = nil
	return err
}

// SetDeadline sets read and write deadlines on both connections.
func (c *UDPHopConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	c.readDeadline = t
	c.writeDeadline = t
	if c.prevConn != nil {
		_ = c.prevConn.SetDeadline(t)
	}
	return c.currentConn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline.
func (c *UDPHopConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = time.Time{}
	c.readDeadline = t
	if c.prevConn != nil {
		_ = c.prevConn.SetReadDeadline(t)
	}
	return c.currentConn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline.
func (c *UDPHopConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = time.Time{}
	c.writeDeadline = t
	if c.prevConn != nil {
		_ = c.prevConn.SetWriteDeadline(t)
	}
	return c.currentConn.SetWriteDeadline(t)
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal goroutines
// ─────────────────────────────────────────────────────────────────────────────

// recvLoop reads packets from conn and puts them on recvQueue until conn is closed.
func (c *UDPHopConn) recvLoop(conn net.PacketConn) {
	for {
		bufPtr := c.bufPool.Get().(*[]byte)
		buf := *bufPtr
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			c.bufPool.Put(bufPtr)
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// Pass through timeout; let ReadFrom surface it
				select {
				case c.recvQueue <- &udpHopPacket{err: err}:
				default:
				}
				continue
			}
			return // conn closed — exit goroutine
		}
		pkt := &udpHopPacket{buf: buf, n: n, addr: addr}
		select {
		case c.recvQueue <- pkt:
		default:
			// Queue full — drop packet (same as Hysteria2)
			c.bufPool.Put(bufPtr)
		}
	}
}

// hopLoop triggers a port hop every hopInterval.
func (c *UDPHopConn) hopLoop() {
	next := c.randomInterval()
	timer := time.NewTimer(next)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			c.hop()
			next = c.randomInterval()
			timer.Reset(next)
		case <-c.closeChan:
			return
		}
	}
}

// hop opens a new UDP socket, moves currentConn → prevConn (closing old prevConn),
// and starts a recvLoop on the new socket.
func (c *UDPHopConn) hop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	newConn, err := c.listenFn()
	if err != nil {
		return // skip this hop
	}

	// Apply buffering / deadline settings to new conn
	if c.readBufSize > 0 {
		if sc, ok := newConn.(interface{ SetReadBuffer(int) error }); ok {
			_ = sc.SetReadBuffer(c.readBufSize)
		}
	}
	if c.writeBufSize > 0 {
		if sc, ok := newConn.(interface{ SetWriteBuffer(int) error }); ok {
			_ = sc.SetWriteBuffer(c.writeBufSize)
		}
	}
	if !c.deadline.IsZero() {
		_ = newConn.SetDeadline(c.deadline)
	} else {
		if !c.readDeadline.IsZero() {
			_ = newConn.SetReadDeadline(c.readDeadline)
		}
		if !c.writeDeadline.IsZero() {
			_ = newConn.SetWriteDeadline(c.writeDeadline)
		}
	}

	// Rotate: close prev (if any), prev = current, current = new
	if c.prevConn != nil {
		_ = c.prevConn.Close()
	}
	c.prevConn = c.currentConn
	c.currentConn = newConn
	c.addrIndex = c.rng.Intn(len(c.remoteAddrs))

	go c.recvLoop(newConn)
}

// randomInterval returns a random duration in [hopInterval.Min, hopInterval.Max].
func (c *UDPHopConn) randomInterval() time.Duration {
	if c.hopInterval.Min == c.hopInterval.Max {
		return c.hopInterval.Min
	}
	delta := int64(c.hopInterval.Max - c.hopInterval.Min)
	return c.hopInterval.Min + time.Duration(c.rng.Int63n(delta+1))
}

// ParseUDPHopPorts parses a port range string like "20000-30000" into a list
// of UDPAddr entries for a given host. Used to construct remoteAddrs for NewUDPHopConn.
func ParseUDPHopPorts(host, portRange string) ([]net.UDPAddr, error) {
	var low, high int
	if _, err := fmt.Sscanf(portRange, "%d-%d", &low, &high); err != nil {
		// Try single port
		var single int
		if _, err2 := fmt.Sscanf(portRange, "%d", &single); err2 != nil {
			return nil, fmt.Errorf("udp_hop: invalid port range %q", portRange)
		}
		low, high = single, single
	}
	if low < 1 || high > 65535 || low > high {
		return nil, fmt.Errorf("udp_hop: port range out of bounds: %d-%d", low, high)
	}
	addrs := make([]net.UDPAddr, 0, high-low+1)
	for port := low; port <= high; port++ {
		addrs = append(addrs, net.UDPAddr{IP: net.ParseIP(host), Port: port})
	}
	return addrs, nil
}
