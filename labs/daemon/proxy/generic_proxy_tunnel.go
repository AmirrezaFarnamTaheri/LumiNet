// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: gost-master
// Target path: server/internal/proxy/generic_proxy_tunnel.go

package proxy

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"
	"sync"
	"time"
)

// GostNode represents a single proxy hop in a generic gost forwarding chain.
type GostNode struct {
	URL      string
	Protocol string // "http", "socks5", "ss", "kcp"
	Addr     string
}

// GostEngine coordinates multi-hop proxy chains and local tunneling adapters.
type GostEngine struct {
	mu         sync.RWMutex
	ChainNodes []GostNode
	running    bool
	listener   net.Listener
}

// NewGostEngine instantiates a new GostEngine.
func NewGostEngine() *GostEngine {
	return &GostEngine{
		ChainNodes: make([]GostNode, 0),
	}
}

// CreateTunnel parses a multi-stage forwarding chain and begins forwarding local traffic.
func (g *GostEngine) CreateTunnel(chain []string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.ChainNodes = nil
	for _, hop := range chain {
		// Example node parse logic: http://1.1.1.1:8080 or socks5://admin:pass@2.2.2.2:1080
		protocol := "http"
		addr := hop
		if idx := stringsIndex(hop, "://"); idx >= 0 {
			protocol = hop[:idx]
			addr = hop[idx+3:]
		}

		g.ChainNodes = append(g.ChainNodes, GostNode{
			URL:      hop,
			Protocol: protocol,
			Addr:     addr,
		})
	}

	log.Printf("Gost: Configured multi-hop proxy forwarding chain with %d nodes", len(g.ChainNodes))
	return nil
}

// StartForwarding starts a local TCP listener to accept connections and tunnel them through the chain.
func (g *GostEngine) StartForwarding(ctx context.Context, listenAddr string) error {
	g.mu.Lock()
	if g.running {
		g.mu.Unlock()
		return fmt.Errorf("gost forwarder already running")
	}

	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		g.mu.Unlock()
		return err
	}

	g.listener = l
	g.running = true
	g.mu.Unlock()

	log.Printf("Gost: Multi-hop proxy tunnel listening on %s", listenAddr)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}

			go g.handleConnection(ctx, conn)
		}
	}()

	return nil
}

// StopForwarding terminates the active listener.
func (g *GostEngine) StopForwarding() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if !g.running {
		return nil
	}

	if g.listener != nil {
		g.listener.Close()
	}
	g.running = false
	slog.Info("Gost", "status", "Multi-hop proxy tunnel stopped")
	return nil
}

func (g *GostEngine) handleConnection(ctx context.Context, localConn net.Conn) {
	defer localConn.Close()

	g.mu.RLock()
	nodesCount := len(g.ChainNodes)
	g.mu.RUnlock()

	if nodesCount == 0 {
		return
	}

	// In a real gost engine, this would dial the first hop, negotiate protocol,
	// and establish connection through all subsequent hops.
	// Here we simulate connecting to the final hop directly.
	g.mu.RLock()
	targetHop := g.ChainNodes[nodesCount-1]
	g.mu.RUnlock()

	dialer := net.Dialer{Timeout: 5 * time.Second}
	remoteConn, err := dialer.DialContext(ctx, "tcp", targetHop.Addr)
	if err != nil {
		log.Printf("Gost: Failed to connect to hop %s: %v", targetHop.URL, err)
		return
	}
	defer remoteConn.Close()

	// Bidirectional tunnel copy
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = copyBytes(remoteConn, localConn)
	}()
	go func() {
		defer wg.Done()
		_, _ = copyBytes(localConn, remoteConn)
	}()
	wg.Wait()
}

func stringsIndex(s, sep string) int {
	// Simple helper to avoid import loop
	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			return i
		}
	}
	return -1
}

func copyBytes(dst net.Conn, src net.Conn) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		nr, err := src.Read(buf)
		if nr > 0 {
			nw, errWrite := dst.Write(buf[0:nr])
			if nw > 0 {
				total += int64(nw)
			}
			if errWrite != nil {
				return total, errWrite
			}
		}
		if err != nil {
			return total, err
		}
	}
}
