// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: XHTTPRelay-main
// Target path: server/internal/proxy/xhttp_relay.go

package proxy

import (
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// XHTTPRelay is the high-performance Vercel Edge Runtime proxy relay.
type XHTTPRelay struct {
	authKey string
}

// NewXHTTPRelay instantiates a new XHTTPRelay.
func NewXHTTPRelay(key string) *XHTTPRelay {
	return &XHTTPRelay{authKey: key}
}

// HandleRelay proxies traffic with custom query filtering and tracking header scrubbers.
func (x *XHTTPRelay) HandleRelay(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("X-Auth-Key")
	if key != x.authKey {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	target := r.Header.Get("X-Target-URL")
	if target == "" {
		http.Error(w, "Missing X-Target-URL header", http.StatusBadRequest)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Clone headers and scrub tracking footprints
	for k, vv := range r.Header {
		lowerK := strings.ToLower(k)
		if strings.HasPrefix(lowerK, "x-vercel-") || lowerK == "x-forwarded-for" || lowerK == "x-real-ip" || lowerK == "cf-connecting-ip" || lowerK == "host" {
			continue // Scrub tracking headers
		}
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)

	log.Printf("XHTTPRelay: Successfully proxied request to %s", target)
}
