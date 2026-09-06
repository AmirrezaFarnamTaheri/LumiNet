// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: XHTTPRelay-main
// Target path: server/internal/proxy/xhttp_relay_vercel.go

package proxy

import (
	"net/http"
)

// XHTTPRelayVercel implements Vercel Edge Runtime serverless relay and method filters.
type XHTTPRelayVercel struct {
	relay *XHTTPRelay
}

// NewXHTTPRelayVercel instantiates a new XHTTPRelayVercel.
func NewXHTTPRelayVercel(key string) *XHTTPRelayVercel {
	return &XHTTPRelayVercel{
		relay: NewXHTTPRelay(key),
	}
}

// ServeHTTP handles incoming requests, filtering methods.
func (x *XHTTPRelayVercel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only allow GET, POST, CONNECT
	if r.Method != "GET" && r.Method != "POST" && r.Method != "CONNECT" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	x.relay.HandleRelay(w, r)
}

// Handle is the legacy diagnostic entry trigger.
func (x *XHTTPRelayVercel) Handle() {
	// Diagnostic stub
}
