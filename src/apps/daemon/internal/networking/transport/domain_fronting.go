package transport

import (
	"fmt"
	"net/http"
	"strings"
)

// DomainFrontingConfig holds parameters for CDN fronting evasion.
type DomainFrontingConfig struct {
	FrontDomain  string            `json:"front_domain"`  // Domain sent in TLS SNI
	OriginHost   string            `json:"origin_host"`   // True target host header
	TargetURI    string            `json:"target_uri"`    // Resource path
	CustomHeaders map[string]string `json:"custom_headers"`
}

// FrontedRequest represents the prepared request ready for transport.
type FrontedRequest struct {
	SNIHost     string            `json:"sni_host"`
	HostHeader  string            `json:"host_header"`
	RequestURI  string            `json:"request_uri"`
	Headers     map[string]string `json:"headers"`
	RawPayload  string            `json:"raw_payload"`
}

// BuildFrontedRequest crafts an evasive fronted request structure.
func BuildFrontedRequest(cfg DomainFrontingConfig, method string) (*FrontedRequest, error) {
	if cfg.FrontDomain == "" {
		return nil, fmt.Errorf("front domain cannot be empty")
	}
	if cfg.OriginHost == "" {
		return nil, fmt.Errorf("origin host cannot be empty")
	}
	if cfg.TargetURI == "" {
		cfg.TargetURI = "/"
	}
	if method == "" {
		method = http.MethodGet
	}

	headers := make(map[string]string)
	headers["Host"] = cfg.OriginHost
	headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	headers["Accept"] = "*/*"

	for k, v := range cfg.CustomHeaders {
		headers[k] = v
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, cfg.TargetURI))
	sb.WriteString(fmt.Sprintf("Host: %s\r\n", cfg.OriginHost))
	for k, v := range headers {
		if k == "Host" {
			continue
		}
		sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	sb.WriteString("\r\n")

	return &FrontedRequest{
		SNIHost:    cfg.FrontDomain,
		HostHeader: cfg.OriginHost,
		RequestURI: cfg.TargetURI,
		Headers:    headers,
		RawPayload: sb.String(),
	}, nil
}
