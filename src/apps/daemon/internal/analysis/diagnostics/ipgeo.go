// Package diagnostics provides geo-IP lookup utilities.
// (formerly package ipgeo) multi-source IP geolocation with SOCKS proxy support.
//
// Implements:
//   - 4-source fallback cascade (ipwho.is, ip.sb, ipapi.co, ipinfo.io)
//   - SOCKS5 proxy-aware HTTP client when VPN is connected
//   - Exponential backoff retry (attempt * 2 seconds)
//   - ASN / org / city / region enrichment alongside country
package diagnostics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// GeoInfo holds the fields extracted from a successful IP geolocation lookup.
type GeoInfo struct {
	Country string
	IP      string
	City    string
	Region  string
	ASN     string // ASN or org string, whichever is available
}

// source describes a geolocation API endpoint and its JSON response parser.
type source struct {
	URL    string
	parser func(map[string]interface{}) GeoInfo
}

// sources lists the fallback cascade used by detectRealCountry.
// Order: ipwho.is → ip.sb → ipapi.co → ipinfo.io
var sources = []source{
	{
		URL: "https://ipwho.is/",
		parser: func(d map[string]interface{}) GeoInfo {
			asn := ""
			if conn, ok := d["connection"].(map[string]interface{}); ok {
				asn = str(conn, "asn")
				if asn == "" {
					asn = str(conn, "org")
				}
			}
			return GeoInfo{
				Country: upper(str(d, "country_code")),
				IP:      str(d, "ip"),
				City:    str(d, "city"),
				Region:  str(d, "region"),
				ASN:     asn,
			}
		},
	},
	{
		URL: "https://api.ip.sb/geoip/",
		parser: func(d map[string]interface{}) GeoInfo {
			asn := str(d, "asn")
			if asn == "" {
				asn = str(d, "organization")
			}
			return GeoInfo{
				Country: upper(str(d, "country_code")),
				IP:      str(d, "ip"),
				City:    str(d, "city"),
				Region:  str(d, "region"),
				ASN:     asn,
			}
		},
	},
	{
		URL: "https://ipapi.co/json/",
		parser: func(d map[string]interface{}) GeoInfo {
			asn := str(d, "asn")
			if asn == "" {
				asn = str(d, "org")
			}
			return GeoInfo{
				Country: upper(str(d, "country_code")),
				IP:      str(d, "ip"),
				City:    str(d, "city"),
				Region:  str(d, "region"),
				ASN:     asn,
			}
		},
	},
	{
		URL: "https://ipinfo.io/json",
		parser: func(d map[string]interface{}) GeoInfo {
			return GeoInfo{
				Country: upper(str(d, "country")),
				IP:      str(d, "ip"),
				City:    str(d, "city"),
				Region:  str(d, "region"),
				ASN:     str(d, "org"),
			}
		},
	},
}

// LookupOptions controls HTTP transport for DetectGeoInfo.
type LookupOptions struct {
	// SocksProxy, if non-empty, routes all requests through this SOCKS5 proxy
	// (e.g. "localhost:10808"). Use when the tunnel is active to detect the
	// apparent exit IP rather than the real device IP.
	SocksProxy string

	// MaxRetries is the number of outer retry loops across all sources.
	// Default (0) is treated as 3.
	MaxRetries int

	// PerSourceTimeout is the per-request deadline. Default is 10 seconds.
	PerSourceTimeout time.Duration
}

// DetectGeoInfo probes geo-IP sources and returns the first successful result.
//   - SOCKS5-aware HttpClient.findProxy equivalent
//   - 4-source cascade with graceful fallthrough
//   - Exponential backoff between retry loops (attempt*2 sec)
func DetectGeoInfo(ctx context.Context, opts LookupOptions) (*GeoInfo, error) {
	maxRetries := opts.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 3
	}
	perSrc := opts.PerSourceTimeout
	if perSrc <= 0 {
		perSrc = 10 * time.Second
	}

	client := buildHTTPClient(opts.SocksProxy, perSrc)

	for attempt := 1; attempt <= maxRetries; attempt++ {
		for _, s := range sources {
			info, err := fetchGeoInfo(ctx, client, s, perSrc)
			if err == nil && info.Country != "" && info.IP != "" {
				return info, nil
			}
		}
		if attempt < maxRetries {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt*2) * time.Second):
			}
		}
	}
	return nil, fmt.Errorf("ipgeo: all %d retry attempts exhausted", maxRetries)
}

func fetchGeoInfo(ctx context.Context, client *http.Client, s source, timeout time.Duration) (*GeoInfo, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, s.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, s.URL)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	info := s.parser(data)
	return &info, nil
}

// buildHTTPClient constructs an http.Client that optionally routes through a
// SOCKS5 proxy.  Mirrors ZedSecure's HttpClient.findProxy logic.
func buildHTTPClient(socksProxy string, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}
	if socksProxy != "" {
		proxyURL, err := url.Parse("socks5://" + socksProxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	return &http.Client{Transport: transport, Timeout: timeout + 2*time.Second}
}

func str(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func upper(s string) string {
	if len(s) == 0 {
		return s
	}
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}
