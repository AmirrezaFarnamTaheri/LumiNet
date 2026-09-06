// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: gfw_resist_tcp_proxy-main
// Target path: server/internal/proxy/gfw_resist_tcp.go

package proxy

import (
	"io"
	"log"
	"net"
	"sync"
	"syscall"
	"time"
)

const (
	tcpMaxSeg = 0x2
)

// GFWResistTCP bypasses GFW/DPI inspection using raw socket TCP packet splitting.
type GFWResistTCP struct {
	SegmentSize int
	WriteDelay  time.Duration
	MSS         int
	WindowScale int
	SACKEnabled bool
}

// NewGFWResistTCP instantiates a new GFWResistTCP proxy controller.
func NewGFWResistTCP() *GFWResistTCP {
	return &GFWResistTCP{
		SegmentSize: 5, // Send in 5-byte tiny fragments
		WriteDelay:  10 * time.Millisecond,
		MSS:         1280,
		WindowScale: 8,
		SACKEnabled: true,
	}
}

// ConfigureTCPSocket applies raw socket-level TCP options.
func (g *GFWResistTCP) ConfigureTCPSocket(conn *net.TCPConn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	var controlErr error
	err = rawConn.Control(func(fd uintptr) {
		// 1. Configure MSS (Maximum Segment Size)
		controlErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_TCP, tcpMaxSeg, g.MSS)
		if controlErr != nil {
			log.Printf("GFWResistTCP: Failed to set TCP_MAXSEG: %v", controlErr)
		}
	})

	if err != nil {
		return err
	}
	return controlErr
}

// ProxyTCP forwards traffic between a local connection and a remote target using fragmented writes and socket tuning.
func (g *GFWResistTCP) ProxyTCP(clientConn net.Conn, targetAddr string) error {
	defer clientConn.Close()

	dialer := net.Dialer{Timeout: 5 * time.Second}
	remoteConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		return err
	}
	defer remoteConn.Close()

	// Apply socket options to remote TCP connection if applicable
	if tcpConn, ok := remoteConn.(*net.TCPConn); ok {
		_ = g.ConfigureTCPSocket(tcpConn)
	}

	// Implement fragmented write wrapper for client -> remote stream
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			nr, err := clientConn.Read(buf)
			if nr > 0 {
				// Fragment the payload into tiny slices with delay
				payload := buf[0:nr]
				for i := 0; i < len(payload); i += g.SegmentSize {
					end := i + g.SegmentSize
					if end > len(payload) {
						end = len(payload)
					}
					_, writeErr := remoteConn.Write(payload[i:end])
					if writeErr != nil {
						return
					}
					time.Sleep(g.WriteDelay)
				}
			}
			if err != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, remoteConn)
	}()

	wg.Wait()
	return nil
}

// Proxy is the legacy entry trigger.
func (g *GFWResistTCP) Proxy() {
	// Diagnostic stub
}
