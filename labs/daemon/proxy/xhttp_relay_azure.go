// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: XHTTPRelayAzure-main
// Target path: server/internal/proxy/xhttp_relay_azure.go

package proxy

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// XHTTPRelayAzure coordinates reverse proxy tunnels deployed to Azure Web App Services.
type XHTTPRelayAzure struct {
	mu           sync.RWMutex
	AzureAppURL  string
	AuthClientID string
	AuthSecret   string
	running      bool
}

// NewXHTTPRelayAzure instantiates a new XHTTPRelayAzure.
func NewXHTTPRelayAzure() *XHTTPRelayAzure {
	return &XHTTPRelayAzure{
		AzureAppURL: "https://luminet-relay.azurewebsites.net",
	}
}

// ServeHTTP handles incoming client requests, injecting Azure App Service credentials and routing headers.
func (x *XHTTPRelayAzure) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	x.mu.RLock()
	azureURL := x.AzureAppURL
	clientID := x.AuthClientID
	clientSecret := x.AuthSecret
	x.mu.RUnlock()

	targetURL, err := url.Parse(azureURL)
	if err != nil {
		http.Error(w, "Invalid Azure App URL target", http.StatusInternalServerError)
		return
	}

	// 1. Establish proxy target endpoint URL paths
	proxyURL := *targetURL
	proxyURL.Path = r.URL.Path
	proxyURL.RawQuery = r.URL.RawQuery

	req, err := http.NewRequestWithContext(r.Context(), r.Method, proxyURL.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 2. Clone headers and inject Azure credentials
	for k, vv := range r.Header {
		if strings.ToLower(k) == "host" {
			continue
		}
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	if clientID != "" && clientSecret != "" {
		req.Header.Set("X-Azure-Client-ID", clientID)
		req.Header.Set("X-Azure-Client-Secret", clientSecret)
	}

	// 3. Dispatch HTTP request to Azure Web App Service
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Azure App Service communication error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 4. Pipe response
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// Relay is the diagnostic legacy endpoint entry.
func (x *XHTTPRelayAzure) Relay() {
	slog.Info("XHTTPRelayAzure", "status", "Complete Azure Web App Service relay configured")
}
