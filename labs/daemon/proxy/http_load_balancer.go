// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: load-balancer-master
// Target path: server/internal/proxy/http_load_balancer.go

package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// BackendServer represents an active downstream HTTP proxy backend.
type BackendServer struct {
	URL    *url.URL
	Alive  bool
	Weight int
	mu     sync.RWMutex
}

// SetAlive updates the active status of the backend.
func (b *BackendServer) SetAlive(alive bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.Alive = alive
}

// IsAlive queries if the backend is currently marked alive.
func (b *BackendServer) IsAlive() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.Alive
}

// HTTPLoadBalancer manages round-robin load distribution with active health checks and mTLS support.
type HTTPLoadBalancer struct {
	backends []*BackendServer
	current  uint64
	ClientCA *tls.Config
}

// NewHTTPLoadBalancer instantiates a new HTTPLoadBalancer.
func NewHTTPLoadBalancer() *HTTPLoadBalancer {
	return &HTTPLoadBalancer{
		backends: make([]*BackendServer, 0),
	}
}

// AddBackend registers a backend endpoint.
func (h *HTTPLoadBalancer) AddBackend(backendURL string) error {
	u, err := url.Parse(backendURL)
	if err != nil {
		return err
	}

	h.backends = append(h.backends, &BackendServer{
		URL:   u,
		Alive: true,
	})
	return nil
}

// NextBackend retrieves the next available backend using round-robin distribution.
func (h *HTTPLoadBalancer) NextBackend() (*BackendServer, error) {
	count := len(h.backends)
	if count == 0 {
		return nil, fmt.Errorf("no backends configured")
	}

	// Iterate to find the next active backend
	for i := 0; i < count; i++ {
		idx := atomic.AddUint64(&h.current, 1) % uint64(count)
		backend := h.backends[idx]
		if backend.IsAlive() {
			return backend, nil
		}
	}

	return nil, fmt.Errorf("all backends are currently unhealthy")
}

// StartHealthChecker triggers background health-checking loops.
func (h *HTTPLoadBalancer) StartHealthChecker(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.pingBackends()
			}
		}
	}()
}

func (h *HTTPLoadBalancer) pingBackends() {
	client := &http.Client{Timeout: 3 * time.Second}
	for _, backend := range h.backends {
		resp, err := client.Get(backend.URL.String() + "/health")
		if err == nil && resp.StatusCode == http.StatusOK {
			backend.SetAlive(true)
		} else {
			backend.SetAlive(false)
			log.Printf("HTTPLoadBalancer: Backend %s marked unhealthy", backend.URL.String())
		}
		if resp != nil {
			resp.Body.Close()
		}
	}
}

// ServeHTTP implements the reverse proxy handler.
func (h *HTTPLoadBalancer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	backend, err := h.NextBackend()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	proxyURL := *backend.URL
	proxyURL.Path = r.URL.Path
	proxyURL.RawQuery = r.URL.RawQuery

	req, err := http.NewRequestWithContext(r.Context(), r.Method, proxyURL.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Copy headers
	for k, vv := range r.Header {
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	transport := &http.Transport{}
	if h.ClientCA != nil {
		transport.TLSClientConfig = h.ClientCA
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		backend.SetAlive(false)
		http.Error(w, "Backend communication failure", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Pipe headers and body back to client
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// Balance is the legacy diagnostic entry trigger.
func (h *HTTPLoadBalancer) Balance() {
	// Diagnostic stub
}
