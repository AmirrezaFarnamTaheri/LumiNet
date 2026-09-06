package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// ProxyEndpoint represents a validated proxy target.
type ProxyEndpoint struct {
	URL      string        `json:"url"`
	Protocol string        `json:"protocol"` // http, socks4, socks5
	Latency  time.Duration `json:"latency"`
	LastSeen time.Time     `json:"last_seen"`
	Alive    bool          `json:"alive"`
}

// ProxyHarvester implements automated harvesting, validation, and rotation from Proxify & proxytunnel.
type ProxyHarvester struct {
	mu           sync.RWMutex
	endpoints    []ProxyEndpoint
	currentIndex int
}

// NewProxyHarvester initializes the proxy harvester.
func NewProxyHarvester() *ProxyHarvester {
	return &ProxyHarvester{
		endpoints: make([]ProxyEndpoint, 0),
	}
}

// AddEndpoint adds a raw proxy endpoint string to the corpus.
func (ph *ProxyHarvester) AddEndpoint(rawURL, protocol string) {
	ph.mu.Lock()
	defer ph.mu.Unlock()
	ph.endpoints = append(ph.endpoints, ProxyEndpoint{
		URL:      rawURL,
		Protocol: protocol,
		Alive:    true,
		LastSeen: time.Now(),
	})
}

// GetNextEndpoint retrieves the next available healthy proxy using round-robin rotation.
func (ph *ProxyHarvester) GetNextEndpoint() (*ProxyEndpoint, error) {
	ph.mu.Lock()
	defer ph.mu.Unlock()

	if len(ph.endpoints) == 0 {
		return nil, fmt.Errorf("no proxy endpoints available in pool")
	}

	for i := 0; i < len(ph.endpoints); i++ {
		idx := (ph.currentIndex + i) % len(ph.endpoints)
		ep := &ph.endpoints[idx]
		if ep.Alive {
			ph.currentIndex = (idx + 1) % len(ph.endpoints)
			return ep, nil
		}
	}

	return nil, fmt.Errorf("all proxies currently down")
}

// DialHTTPConnect performs authenticating HTTP CONNECT proxy tunneling (from proxytunnel C spec).
func DialHTTPConnect(ctx context.Context, proxyAddr, targetAddr, username, password string) (net.Conn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy %s: %w", proxyAddr, err)
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)
	if username != "" || password != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}
	connectReq += "User-Agent: LumiNet-ProxyTunnel/2.0\r\n\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send CONNECT request: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read CONNECT response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy returned status: %s", resp.Status)
	}

	return conn, nil
}
