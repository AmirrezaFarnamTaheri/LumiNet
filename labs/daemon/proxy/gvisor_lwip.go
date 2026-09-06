package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// NetstackType defines the userspace networking stack implementation.
type NetstackType string

const (
	NetstackGvisor NetstackType = "gvisor"
	NetstackLwip   NetstackType = "lwip"
	NetstackSystem NetstackType = "system"
)

// UserspaceNetstack provides an interface for interacting with TUN device packets
// using userspace TCP/IP stacks like gVisor or LwIP.
type UserspaceNetstack interface {
	Start(ctx context.Context) error
	Close() error
	AcceptTCP() (net.Conn, error)
	AcceptUDP() (net.PacketConn, error)
}

// virtualConn implements a net.Conn backed by in-memory buffers for userspace routing.
type virtualConn struct {
	localAddr  net.Addr
	remoteAddr net.Addr
	readPipe   *io.PipeReader
	writePipe  *io.PipeWriter
	closeMu    sync.Mutex
	closed     bool
}

func newVirtualConnPair(local, remote net.Addr) (*virtualConn, *virtualConn) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()

	c1 := &virtualConn{
		localAddr:  local,
		remoteAddr: remote,
		readPipe:   r1,
		writePipe:  w2,
	}

	c2 := &virtualConn{
		localAddr:  remote,
		remoteAddr: local,
		readPipe:   r2,
		writePipe:  w1,
	}

	return c1, c2
}

func (c *virtualConn) Read(b []byte) (n int, err error) {
	return c.readPipe.Read(b)
}

func (c *virtualConn) Write(b []byte) (n int, err error) {
	return c.writePipe.Write(b)
}

func (c *virtualConn) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.readPipe.Close()
	c.writePipe.Close()
	return nil
}

func (c *virtualConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *virtualConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *virtualConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *virtualConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *virtualConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// virtualPacketConn implements net.PacketConn for UDP flow routing.
type virtualPacketConn struct {
	localAddr net.Addr
	readChan  chan []byte
	writeChan chan []byte
	closeMu   sync.Mutex
	closed    bool
}

func (p *virtualPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	data, ok := <-p.readChan
	if !ok {
		return 0, nil, io.EOF
	}
	copy(b, data)
	n = len(data)
	if n > len(b) {
		n = len(b)
	}
	return n, p.localAddr, nil
}

func (p *virtualPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	if p.closed {
		return 0, net.ErrClosed
	}
	p.writeChan <- append([]byte(nil), b...)
	return len(b), nil
}

func (p *virtualPacketConn) Close() error {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	close(p.readChan)
	return nil
}

func (p *virtualPacketConn) LocalAddr() net.Addr {
	return p.localAddr
}

func (p *virtualPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (p *virtualPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (p *virtualPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// gvisorNetstack implements a minimal stub for the gVisor netstack.
type gvisorNetstack struct {
	tunDevice io.ReadWriteCloser
	tcpChan   chan net.Conn
	udpChan   chan net.PacketConn
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// NewGvisorStack creates a new gVisor-compatible userspace network stack.
func NewGvisorStack(tun io.ReadWriteCloser) UserspaceNetstack {
	return &gvisorNetstack{
		tunDevice: tun,
		tcpChan:   make(chan net.Conn, 128),
		udpChan:   make(chan net.PacketConn, 128),
	}
}

func (g *gvisorNetstack) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	g.cancel = cancel

	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		buf := make([]byte, 1600)
		for {
			select {
			case <-runCtx.Done():
				return
			default:
			}

			n, err := g.tunDevice.Read(buf)
			if err != nil {
				return
			}
			if n < 20 {
				continue
			}

			packet := buf[:n]
			version := packet[0] >> 4
			if version != 4 {
				continue
			}

			proto := packet[9]
			srcIP := net.IP(packet[12:16])
			dstIP := net.IP(packet[16:20])
			headerLen := int(packet[0]&0x0f) * 4

			if proto == 6 && headerLen+20 <= len(packet) { // TCP
				srcPort := binary.BigEndian.Uint16(packet[headerLen : headerLen+2])
				dstPort := binary.BigEndian.Uint16(packet[headerLen+2 : headerLen+4])

				local := &net.TCPAddr{IP: srcIP, Port: int(srcPort)}
				remote := &net.TCPAddr{IP: dstIP, Port: int(dstPort)}

				c1, _ := newVirtualConnPair(local, remote)
				select {
				case g.tcpChan <- c1:
				default:
				}
			} else if proto == 17 && headerLen+8 <= len(packet) { // UDP
				srcPort := binary.BigEndian.Uint16(packet[headerLen : headerLen+2])
				local := &net.UDPAddr{IP: srcIP, Port: int(srcPort)}

				pConn := &virtualPacketConn{
					localAddr: local,
					readChan:  make(chan []byte, 32),
					writeChan: make(chan []byte, 32),
				}
				select {
				case g.udpChan <- pConn:
				default:
				}
			}
		}
	}()

	return nil
}

func (g *gvisorNetstack) Close() error {
	if g.cancel != nil {
		g.cancel()
	}
	g.tunDevice.Close()
	g.wg.Wait()
	return nil
}

func (g *gvisorNetstack) AcceptTCP() (net.Conn, error) {
	conn, ok := <-g.tcpChan
	if !ok {
		return nil, errors.New("netstack closed")
	}
	return conn, nil
}

func (g *gvisorNetstack) AcceptUDP() (net.PacketConn, error) {
	conn, ok := <-g.udpChan
	if !ok {
		return nil, errors.New("netstack closed")
	}
	return conn, nil
}

// lwipNetstack implements a minimal stub for the LwIP netstack.
type lwipNetstack struct {
	tunDevice io.ReadWriteCloser
	tcpChan   chan net.Conn
	udpChan   chan net.PacketConn
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// NewLwipStack creates a new LwIP-compatible userspace network stack.
func NewLwipStack(tun io.ReadWriteCloser) UserspaceNetstack {
	return &lwipNetstack{
		tunDevice: tun,
		tcpChan:   make(chan net.Conn, 128),
		udpChan:   make(chan net.PacketConn, 128),
	}
}

func (l *lwipNetstack) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	l.cancel = cancel

	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		buf := make([]byte, 1600)
		for {
			select {
			case <-runCtx.Done():
				return
			default:
			}

			n, err := l.tunDevice.Read(buf)
			if err != nil {
				return
			}
			if n < 20 {
				continue
			}

			packet := buf[:n]
			version := packet[0] >> 4
			if version != 4 {
				continue
			}

			proto := packet[9]
			srcIP := net.IP(packet[12:16])
			dstIP := net.IP(packet[16:20])
			headerLen := int(packet[0]&0x0f) * 4

			if proto == 6 && headerLen+20 <= len(packet) { // TCP
				srcPort := binary.BigEndian.Uint16(packet[headerLen : headerLen+2])
				dstPort := binary.BigEndian.Uint16(packet[headerLen+2 : headerLen+4])

				local := &net.TCPAddr{IP: srcIP, Port: int(srcPort)}
				remote := &net.TCPAddr{IP: dstIP, Port: int(dstPort)}

				c1, _ := newVirtualConnPair(local, remote)
				select {
				case l.tcpChan <- c1:
				default:
				}
			} else if proto == 17 && headerLen+8 <= len(packet) { // UDP
				srcPort := binary.BigEndian.Uint16(packet[headerLen : headerLen+2])
				local := &net.UDPAddr{IP: srcIP, Port: int(srcPort)}

				pConn := &virtualPacketConn{
					localAddr: local,
					readChan:  make(chan []byte, 32),
					writeChan: make(chan []byte, 32),
				}
				select {
				case l.udpChan <- pConn:
				default:
				}
			}
		}
	}()

	return nil
}

func (l *lwipNetstack) Close() error {
	if l.cancel != nil {
		l.cancel()
	}
	l.tunDevice.Close()
	l.wg.Wait()
	return nil
}

func (l *lwipNetstack) AcceptTCP() (net.Conn, error) {
	conn, ok := <-l.tcpChan
	if !ok {
		return nil, errors.New("netstack closed")
	}
	return conn, nil
}

func (l *lwipNetstack) AcceptUDP() (net.PacketConn, error) {
	conn, ok := <-l.udpChan
	if !ok {
		return nil, errors.New("netstack closed")
	}
	return conn, nil
}
