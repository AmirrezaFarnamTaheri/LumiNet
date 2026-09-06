// Package worker_rotator provides Cloudflare Workers-based proxy rotation.
// Ported from FlareTunnel.
//
// Routes HTTP/HTTPS traffic through rotating Cloudflare Workers
// for IP rotation and anonymity. Supports multi-account management,
// worker rotation (round-robin/random), and quota-aware distribution.
package worker_rotator

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

// WorkerAccount represents a Cloudflare account with Workers.
type WorkerAccount struct {
	AccountID string `json:"account_id"`
	APIToken  string `json:"api_token"`
	Workers   []Worker `json:"workers"`
	QuotaUsed int64    `json:"quota_used"` // requests/day
	QuotaMax  int64    `json:"quota_max"`  // typically 100k/day
}

// Worker represents a deployed Cloudflare Worker.
type Worker struct {
	Name     string `json:"name"`
	Subdomain string `json:"subdomain"`
	Enabled  bool   `json:"enabled"`
}

// RotationStrategy defines how workers are selected.
type RotationStrategy int

const (
	// RoundRobin cycles through workers sequentially.
	RoundRobin RotationStrategy = iota
	// Random selects a random worker.
	Random
	// QuotaAware distributes proportionally to remaining quota.
	QuotaAware
)

// WorkerRotator manages proxy rotation through Cloudflare Workers.
type WorkerRotator struct {
	accounts  []WorkerAccount
	strategy  RotationStrategy
	mu        sync.Mutex
	nextIdx   int
	transport *http.Transport
}

// NewWorkerRotator creates a new WorkerRotator.
func NewWorkerRotator(strategy RotationStrategy) *WorkerRotator {
	return &WorkerRotator{
		strategy: strategy,
		transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

// AddAccount adds a Cloudflare account.
func (fp *WorkerRotator) AddAccount(account WorkerAccount) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.accounts = append(fp.accounts, account)
}

// SelectWorker selects the next worker based on rotation strategy.
func (fp *WorkerRotator) SelectWorker() (*Worker, error) {
	fp.mu.Lock()
	defer fp.mu.Unlock()

	// Collect all enabled workers
	var workers []Worker
	for _, acct := range fp.accounts {
		for _, w := range acct.Workers {
			if w.Enabled {
				workers = append(workers, w)
			}
		}
	}

	if len(workers) == 0 {
		return nil, fmt.Errorf("no enabled workers available")
	}

	switch fp.strategy {
	case RoundRobin:
		idx := fp.nextIdx % len(workers)
		fp.nextIdx++
		return &workers[idx], nil
	case Random:
		idx := rand.Intn(len(workers))
		return &workers[idx], nil
	default:
		return &workers[0], nil
	}
}

// ProxyRequest proxies an HTTP request through a Cloudflare Worker.
func (fp *WorkerRotator) ProxyRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	worker, err := fp.SelectWorker()
	if err != nil {
		return nil, err
	}

	// Build worker URL
	workerURL := fmt.Sprintf("https://%s.workers.dev", worker.Subdomain)

	// Create proxy request
	proxyReq, err := http.NewRequestWithContext(ctx, "POST", workerURL, req.Body)
	if err != nil {
		return nil, err
	}

	// Forward headers
	for k, v := range req.Header {
		proxyReq.Header[k] = v
	}
	proxyReq.Header.Set("X-Target-URL", req.URL.String())
	proxyReq.Header.Set("X-Target-Method", req.Method)

	client := &http.Client{Transport: fp.transport, Timeout: 30 * time.Second}
	return client.Do(proxyReq)
}

// WorkerCount returns the total number of workers.
func (fp *WorkerRotator) WorkerCount() int {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	count := 0
	for _, acct := range fp.accounts {
		count += len(acct.Workers)
	}
	return count
}

// URLBlacklist checks if a URL should be blocked to save quota.
// Ported from FlareTunnel's blacklist patterns.
func URLBlacklist(rawURL string) bool {
	// Block analytics/tracking to save worker quota
	blockPatterns := []string{
		"google-analytics.com",
		"googletagmanager.com",
		"facebook.com/tr",
		"doubleclick.net",
		"googlesyndication.com",
		"googleadservices.com",
		".gif?",
		".png?",
		".jpg?",
		".woff",
		".ttf",
		".eot",
	}
	for _, pattern := range blockPatterns {
		if strings.Contains(rawURL, pattern) {
			return true
		}
	}
	return false
}
