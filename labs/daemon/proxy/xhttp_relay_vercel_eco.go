// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: XHTTPRelayECO-master
// Target path: server/internal/proxy/xhttp_relay_vercel_eco.go

package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// XHTTPRelayVercelEco handles Vercel Edge Runtime style serverless relaying with scrubbing & throttle rules.
type XHTTPRelayVercelEco struct {
	TargetDomain string
	RelayKey     string
	MaxUpBps     int64
	MaxDownBps   int64
	mu           sync.RWMutex
}

// NewXHTTPRelayVercelEco instantiates a new XHTTPRelayVercelEco.
func NewXHTTPRelayVercelEco() *XHTTPRelayVercelEco {
	return &XHTTPRelayVercelEco{
		TargetDomain: "https://example.com",
		RelayKey:     "default-secret-key-16bytes",
		MaxUpBps:     2621440, // 2.5 MB/s
		MaxDownBps:   2621440, // 2.5 MB/s
	}
}

// ThrottledCopy copies bytes from src to dst, enforcing a rate limit (bytes per second).
func (x *XHTTPRelayVercelEco) ThrottledCopy(dst io.Writer, src io.Reader, maxBps int64) (int64, error) {
	if maxBps <= 0 {
		return io.Copy(dst, src)
	}

	buf := make([]byte, 32*1024) // 32KB buffer
	var totalCopied int64
	start := time.Now()

	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			nw, werr := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if werr == nil {
					werr = io.ErrShortWrite
				}
			}
			totalCopied += int64(nw)
			if werr != nil {
				return totalCopied, werr
			}
			if nr != nw {
				return totalCopied, io.ErrShortWrite
			}

			// Calculate latency delay to match target speed limit
			elapsed := time.Since(start)
			expectedTime := time.Duration(totalCopied) * time.Second / time.Duration(maxBps)
			if elapsed < expectedTime {
				time.Sleep(expectedTime - elapsed)
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return totalCopied, nil
			}
			return totalCopied, rerr
		}
	}
}

// ServeHTTP acts as the HTTP proxy handler, scrubbing tracking headers and applying throttle limits.
func (x *XHTTPRelayVercelEco) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Verify Authentication Key
	authKey := r.Header.Get("X-Relay-Key")
	if x.RelayKey != "" && authKey != x.RelayKey {
		http.Error(w, "Unauthorized relay key", http.StatusUnauthorized)
		return
	}

	// 2. Parse Target Destination
	targetURL, err := url.Parse(x.TargetDomain)
	if err != nil {
		http.Error(w, "Invalid target domain configuration", http.StatusInternalServerError)
		return
	}

	// 3. Clone and Scrub Request Headers
	proxyReqURL := *targetURL
	proxyReqURL.Path = r.URL.Path
	proxyReqURL.RawQuery = r.URL.RawQuery

	req, err := http.NewRequestWithContext(r.Context(), r.Method, proxyReqURL.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Exact headers to strip (tracking prevention)
	stripHeaders := map[string]bool{
		"host":              true,
		"connection":        true,
		"proxy-connection":  true,
		"keep-alive":        true,
		"via":               true,
		"x-forwarded-host":  true,
		"x-forwarded-proto": true,
		"x-forwarded-port":  true,
		"x-forwarded-for":   true,
		"x-real-ip":         true,
	}

	for k, vv := range r.Header {
		lowerKey := strings.ToLower(k)
		// Scrub all Vercel tracking headers
		if strings.HasPrefix(lowerKey, "x-vercel-") {
			continue
		}
		if stripHeaders[lowerKey] {
			continue
		}
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	// 4. Dispatch Upstream Request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Clone response headers (scrubbing target headers)
	for k, vv := range resp.Header {
		lowerKey := strings.ToLower(k)
		if strings.HasPrefix(lowerKey, "x-vercel-") {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// 5. Throttled Body Copy (Download throttling)
	_, _ = x.ThrottledCopy(w, resp.Body, x.MaxDownBps)
}

// Relay is the diagnostic legacy endpoint entry.
func (x *XHTTPRelayVercelEco) Relay() {
	slog.Info("XHTTPRelayVercelEco", "status", "Complete serverless Vercel edge XHTTP relay configured")
}
