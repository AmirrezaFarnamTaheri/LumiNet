// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: torget-main (Project 036)
// Target path: server/internal/proxy/socks5_isolation.go
//
// Parallel multi-circuit range downloading via Tor's SOCKS isolation.
//
// Tor's SOCKS5 listener assigns one circuit per unique (username, password)
// pair. By issuing per-chunk credentials `tg<idx>:tg<idx>@127.0.0.1:9050`,
// each parallel HTTP GET maps to a distinct stream on a distinct circuit,
// forcing Tor to spread the chunks across different exit IPs — the core
// trick from torget. LumiNet uses this for census-style range downloads
// that would otherwise trip per-IP rate limits on a single exit.

package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
)

// IsolationConfig tunes the parallel multi-circuit fetcher.
type IsolationConfig struct {
	SOCKSAddr    string // e.g. "127.0.0.1:9050"
	Concurrency  int    // simultaneous workers; default 4.
	UsernameBase string // prefix for per-worker usernames; default "tg".
}

// IsolationResult is the per-chunk outcome.
type IsolationResult struct {
	Index  int
	Bytes  int64
	ExitOK bool
	Error  error
}

// ParallelMultiCircuitDownload issues `n` independent HTTP GETs through
// the local Tor SOCKS proxy, each forced onto its own circuit via per-chunk
// SOCKS5 credentials. Returns the per-chunk byte counts and exit status.
func ParallelMultiCircuitDownload(ctx context.Context, cfg IsolationConfig, n int, url string) []IsolationResult {
	if cfg.SOCKSAddr == "" {
		cfg.SOCKSAddr = "127.0.0.1:9050"
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 4
	}
	if cfg.UsernameBase == "" {
		cfg.UsernameBase = "tg"
	}

	results := make([]IsolationResult, n)
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup

	for idx := 0; idx < n; idx++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res, err := singleChunkDownload(ctx, cfg, i, url)
			results[i] = IsolationResult{
				Index:  i,
				Bytes:  res,
				ExitOK: err == nil,
				Error:  err,
			}
		}(idx)
	}
	wg.Wait()
	return results
}

func singleChunkDownload(ctx context.Context, cfg IsolationConfig, idx int, target string) (int64, error) {
	user := cfg.UsernameBase + strconv.Itoa(idx)
	proxyURL := &url.URL{
		Scheme: "socks5",
		User:   url.UserPassword(user, user),
		Host:   cfg.SOCKSAddr,
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("socks5_isolation: chunk %d: HTTP %d", idx, resp.StatusCode)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		return n, err
	}
	return n, nil
}
