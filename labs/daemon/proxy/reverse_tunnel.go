package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// ReverseTunnelConfig specifies reverse tunnel endpoints.
type ReverseTunnelConfig struct {
	Enabled        bool   `json:"enabled"`
	ServerAddr     string `json:"server_addr"`      // Address of the remote relay server
	LocalSocksAddr string `json:"local_socks_addr"` // Address to expose locally
	TunnelSecret   string `json:"tunnel_secret"`
}

// ReverseTunnelClient manages outbound multiplexed channels.
type ReverseTunnelClient struct {
	config ReverseTunnelConfig
	mu     sync.Mutex
	active bool
	cancel context.CancelFunc
}

// NewReverseTunnelClient creates a new client instance.
func NewReverseTunnelClient(cfg ReverseTunnelConfig) *ReverseTunnelClient {
	return &ReverseTunnelClient{config: cfg}
}

// Start begins connecting and tunnel multiplexing loop.
func (c *ReverseTunnelClient) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.active {
		c.mu.Unlock()
		return fmt.Errorf("reverse tunnel is already active")
	}
	c.active = true
	tCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.mu.Unlock()

	log.Printf("Starting reverse tunnel client to %s", c.config.ServerAddr)

	go c.reconnectLoop(tCtx)
	return nil
}

// Stop shuts down the client loop.
func (c *ReverseTunnelClient) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.active {
		return
	}
	log.Printf("Stopping reverse tunnel client")
	if c.cancel != nil {
		c.cancel()
	}
	c.active = false
}

func (c *ReverseTunnelClient) reconnectLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := net.DialTimeout("tcp", c.config.ServerAddr, 10*time.Second)
		if err != nil {
			log.Printf("Reverse tunnel dial failed: %v. Retrying in 5 seconds...", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
				continue
			}
		}

		log.Printf("Reverse tunnel connected successfully to %s", c.config.ServerAddr)
		c.handleControlStream(ctx, conn)
	}
}

func (c *ReverseTunnelClient) handleControlStream(ctx context.Context, ctrl net.Conn) {
	defer ctrl.Close()

	// Perform authentication challenge
	_, err := ctrl.Write([]byte(fmt.Sprintf("AUTH:%s\n", c.config.TunnelSecret)))
	if err != nil {
		return
	}

	// Keep alive / ping loop
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, err := ctrl.Write([]byte("PING\n"))
				if err != nil {
					return
				}
			}
		}
	}()

	// Read commands from the control connection
	buf := make([]byte, 1024)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_ = ctrl.SetReadDeadline(time.Now().Add(40 * time.Second))
		n, err := ctrl.Read(buf)
		if err != nil {
			log.Printf("Control connection read error: %v", err)
			return
		}

		cmd := string(buf[:n])
		if cmd == "NEW_CHANNEL" {
			// Connect local SOCKS5 proxy to relay channel
			go c.spawnChannel(ctx)
		}
	}
}

func (c *ReverseTunnelClient) spawnChannel(ctx context.Context) {
	// Connect to local SOCKS
	local, err := net.Dial("tcp", c.config.LocalSocksAddr)
	if err != nil {
		return
	}
	defer local.Close()

	// Connect second channel to remote relay
	remote, err := net.DialTimeout("tcp", c.config.ServerAddr, 5*time.Second)
	if err != nil {
		return
	}
	defer remote.Close()

	// Authenticate channel
	_, err = remote.Write([]byte(fmt.Sprintf("CHANNEL:%s\n", c.config.TunnelSecret)))
	if err != nil {
		return
	}

	// Bridge data bidirectionally
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(remote, local)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(local, remote)
	}()
	wg.Wait()
}
