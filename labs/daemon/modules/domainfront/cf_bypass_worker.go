// Package domainfront implements domain fronting detection and CDN proxying.
// Ported from: cloudflare-bypass-main (worker.js)
// Target path: server/internal/domainfront/cf_bypass_worker.go

package domainfront

import (
	"context"
	"net/http"
	"strings"
)

// CFBypassWorker emulates request forwarding logic from worker.js.
type CFBypassWorker struct {
	TokenHeader string
	TokenValue  string
	HostHeader  string
	IPHeader    string
}

// NewDefaultCFBypassWorker initializes the worker headers.
func NewDefaultCFBypassWorker() *CFBypassWorker {
	return &CFBypassWorker{
		TokenHeader: "Px-Token",
		TokenValue:  "mysecuretoken",
		HostHeader:  "Px-Host",
		IPHeader:    "Px-IP",
	}
}

// ForwardReq checks token authenticity and forwards the request by rewriting headers.
// Maps to javascript forwardReq() in worker.js.
func (w *CFBypassWorker) ForwardReq(ctx context.Context, client *http.Client, req *http.Request) (*http.Response, error) {
	if req.Header.Get(w.TokenHeader) != w.TokenValue {
		// Respond with fallback simulation
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       http.NoBody,
		}
		resp.Header.Set("Content-Type", "text/plain")
		// "Welcome to nginx!" equivalent
		return resp, nil
	}

	cloned := req.Clone(ctx)

	// Clean headers: remove proxy-specific and Cloudflare-injected headers
	cleanHeaders := make(http.Header)
	for k, v := range req.Header {
		lowerKey := strings.ToLower(k)
		if lowerKey == strings.ToLower(w.TokenHeader) ||
			lowerKey == strings.ToLower(w.HostHeader) ||
			lowerKey == strings.ToLower(w.IPHeader) ||
			strings.HasPrefix(lowerKey, "cf-") ||
			lowerKey == "x-forwarded-for" ||
			lowerKey == "x-real-ip" {
			continue
		}
		cleanHeaders[k] = v
	}

	// Update Host and X-Forwarded-For headers
	targetHost := req.Header.Get(w.HostHeader)
	fakeIP := req.Header.Get(w.IPHeader)

	cloned.Header = cleanHeaders
	cloned.Header.Set("Host", targetHost)
	cloned.Header.Set("X-Forwarded-For", fakeIP)

	// Rewrite request URL matching destination host
	cloned.URL.Host = targetHost
	cloned.Host = targetHost

	return client.Do(cloned)
}
