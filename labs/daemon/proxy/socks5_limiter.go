// Ported from: nexus-proxy-master
// Target path: server/internal/proxy/socks5_limiter.go

package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// Socks5Limiter wraps a net.Conn and limits transfer speed.
type Socks5Limiter struct {
	net.Conn
	readLimiter  *BrutalRateController
	writeLimiter *BrutalRateController
}

// NewSocks5Limiter creates a new rate-limited connection.
func NewSocks5Limiter(c net.Conn, rxBps, txBps int64) *Socks5Limiter {
	var rx, tx *BrutalRateController
	if rxBps > 0 {
		rx = NewBrutalRateController(rxBps, 1500)
	}
	if txBps > 0 {
		tx = NewBrutalRateController(txBps, 1500)
	}
	return &Socks5Limiter{
		Conn:         c,
		readLimiter:  rx,
		writeLimiter: tx,
	}
}

// Read overrides net.Conn.Read to apply pacing.
func (c *Socks5Limiter) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil {
		return n, err
	}
	if c.readLimiter != nil && n > 0 {
		_ = c.readLimiter.Pace(context.Background(), n)
	}
	return n, nil
}

// Write overrides net.Conn.Write to apply pacing.
func (c *Socks5Limiter) Write(b []byte) (int, error) {
	if c.writeLimiter != nil && len(b) > 0 {
		_ = c.writeLimiter.Pace(context.Background(), len(b))
	}
	return c.Conn.Write(b)
}

// Socks5Server represents SOCKS5 proxy listener with connection limits.
type Socks5Server struct {
	ListenAddr string
	MaxSpeedRx int64 // bytes per second
	MaxSpeedTx int64
	listener   net.Listener
	wg         sync.WaitGroup
	quit       chan struct{}
}

// NewSocks5Server creates a new SOCKS5 proxy server.
func NewSocks5Server(listen string, rxLimit, txLimit int64) *Socks5Server {
	return &Socks5Server{
		ListenAddr: listen,
		MaxSpeedRx: rxLimit,
		MaxSpeedTx: txLimit,
		quit:       make(chan struct{}),
	}
}

// Start opens SOCKS5 server port.
func (s *Socks5Server) Start() error {
	var err error
	s.listener, err = net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return fmt.Errorf("socks5_limiter: listen failed: %w", err)
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				select {
				case <-s.quit:
					return
				default:
					continue
				}
			}
			go s.handleConnection(conn)
		}
	}()

	return nil
}

func (s *Socks5Server) handleConnection(client net.Conn) {
	defer client.Close()

	// SOCKS5 authentication method selection
	header := make([]byte, 2)
	if _, err := io.ReadFull(client, header); err != nil {
		return
	}
	if header[0] != 0x05 {
		return // SOCKS5 version check
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}

	// Always select "No Authentication" (0x00)
	_, _ = client.Write([]byte{0x05, 0x00})

	// SOCKS5 request parsing
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(client, reqHeader); err != nil {
		return
	}

	cmd := reqHeader[1]
	if cmd != 0x01 { // Connect only
		_, _ = client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Command not supported
		return
	}

	addrType := reqHeader[3]
	var address string
	switch addrType {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(client, ip); err != nil {
			return
		}
		address = net.IP(ip).String()
	case 0x03: // Domain name
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(client, lenByte); err != nil {
			return
		}
		host := make([]byte, int(lenByte[0]))
		if _, err := io.ReadFull(client, host); err != nil {
			return
		}
		address = string(host)
	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(client, ip); err != nil {
			return
		}
		address = net.IP(ip).String()
	default:
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(client, portBuf); err != nil {
		return
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])

	targetAddr := net.JoinHostPort(address, strconv.Itoa(port))
	target, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Host unreachable
		return
	}
	defer target.Close()

	// Respond SOCKS5 connection success
	_, _ = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})

	// Wrap connections in our limiter
	limitedClient := NewSocks5Limiter(client, s.MaxSpeedRx, s.MaxSpeedTx)
	limitedTarget := NewSocks5Limiter(target, s.MaxSpeedRx, s.MaxSpeedTx)

	// Tunnel
	var wg sync.WaitGroup
	wg.Add(2)
	copyStream := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
	}
	go copyStream(limitedTarget, limitedClient)
	go copyStream(limitedClient, limitedTarget)
	wg.Wait()
}

// Stop shuts down the SOCKS5 server.
func (s *Socks5Server) Stop() {
	close(s.quit)
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
}
