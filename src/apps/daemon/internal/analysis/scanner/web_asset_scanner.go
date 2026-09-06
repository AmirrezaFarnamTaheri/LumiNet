// Package scanner implements host and dns probing operations.

package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// WebProbeResult holds HTTP response status, headers, and metadata.
// Maps to C++ HttpProbeResult.
type WebProbeResult struct {
	URL         string            `json:"url"`
	Scheme      string            `json:"scheme"`
	Host        string            `json:"host"`
	Port        int               `json:"port"`
	Path        string            `json:"path"`
	Reachable   bool              `json:"reachable"`
	TLSPortOpen bool              `json:"tls_port_open"`
	StatusCode  int               `json:"status_code"`
	Server      string            `json:"server"`
	Location    string            `json:"location"`
	Headers     map[string]string `json:"headers"`
	BodyPreview string            `json:"body_preview"`
	Redirects   int               `json:"redirects"`
	Error       string            `json:"error"`
}

// Getters & Setters for WebProbeResult
func (r *WebProbeResult) GetURL() string { return r.URL }
func (r *WebProbeResult) SetURL(v string) { r.URL = v }
func (r *WebProbeResult) GetReachable() bool { return r.Reachable }
func (r *WebProbeResult) SetReachable(v bool) { r.Reachable = v }

// WebAssetResult holds the status of resource files checked during scans.
// Maps to C++ WebAssetResult.
type WebAssetResult struct {
	URL        string `json:"url"`
	Reachable  bool   `json:"reachable"`
	StatusCode int    `json:"status_code"`
	Server     string `json:"server"`
	Error      string `json:"error"`
}

// WebAssetScanner performs parallel HTTP checks on root targets and related assets.
// Maps to C++ HttpScanner.
type WebAssetScanner struct {
	mu              sync.Mutex
	targets         []string
	assets          []string
	fetchBody       bool
	followRedirects bool
	timeout         time.Duration
	probeResults    []WebProbeResult
	assetResults    []WebAssetResult
}

// NewWebAssetScanner creates a WebAssetScanner.
func NewWebAssetScanner(targets []string, assets []string, fetchBody bool, followRedirects bool, timeout time.Duration) *WebAssetScanner {
	return &WebAssetScanner{
		targets:         targets,
		assets:          assets,
		fetchBody:       fetchBody,
		followRedirects: followRedirects,
		timeout:         timeout,
	}
}

// ProbeResults returns probe results safely.
func (s *WebAssetScanner) ProbeResults() []WebProbeResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]WebProbeResult(nil), s.probeResults...)
}

// AssetResults returns asset results safely.
func (s *WebAssetScanner) AssetResults() []WebAssetResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]WebAssetResult(nil), s.assetResults...)
}

// Run executes the scanner in parallel across all targets.
// Maps to C++ HttpScanner::run().
func (s *WebAssetScanner) Run(ctx context.Context, concurrency int) {
	if concurrency <= 0 {
		concurrency = 10
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	client := &http.Client{
		Timeout: s.timeout,
	}
	if !s.followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	for _, target := range s.targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			res := s.probeURL(ctx, client, u)
			s.mu.Lock()
			s.probeResults = append(s.probeResults, res)
			s.mu.Unlock()

			// Check sub-assets
			for _, asset := range s.assets {
				wg.Add(1)
				sem <- struct{}{}
				go func(a string) {
					defer wg.Done()
					defer func() { <-sem }()
					assetRes := s.probeAsset(ctx, client, u, a)
					s.mu.Lock()
					s.assetResults = append(s.assetResults, assetRes)
					s.mu.Unlock()
				}(asset)
			}
		}(target)
	}

	wg.Wait()
}

func (s *WebAssetScanner) probeURL(ctx context.Context, client *http.Client, urlStr string) WebProbeResult {
	result := WebProbeResult{
		URL:       urlStr,
		Headers:   make(map[string]string),
		Reachable: false,
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		result.Error = "invalid url: " + err.Error()
		return result
	}

	result.Scheme = u.Scheme
	result.Host = u.Hostname()
	result.Path = u.Path
	if u.Port() != "" {
		var portVal int
		_, _ = fmt.Sscanf(u.Port(), "%d", &portVal)
		result.Port = portVal
	} else if u.Scheme == "https" {
		result.Port = 443
	} else {
		result.Port = 80
	}

	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		result.Error = "create request: " + err.Error()
		return result
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	result.Reachable = true
	result.StatusCode = resp.StatusCode
	result.Server = resp.Header.Get("Server")
	result.Location = resp.Header.Get("Location")

	for k, v := range resp.Header {
		if len(v) > 0 {
			result.Headers[k] = v[0]
		}
	}

	if s.fetchBody {
		limitReader := io.LimitReader(resp.Body, 1024)
		bodyBytes, _ := io.ReadAll(limitReader)
		result.BodyPreview = string(bodyBytes)
	}

	if strings.ToLower(u.Scheme) == "https" {
		result.TLSPortOpen = true
	}

	return result
}

func (s *WebAssetScanner) probeAsset(ctx context.Context, client *http.Client, baseURL, assetPath string) WebAssetResult {
	fullURL := strings.TrimSuffix(baseURL, "/") + "/" + strings.TrimPrefix(assetPath, "/")
	result := WebAssetResult{
		URL:       fullURL,
		Reachable: false,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		result.Error = "create request: " + err.Error()
		return result
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	result.Reachable = true
	result.StatusCode = resp.StatusCode
	result.Server = resp.Header.Get("Server")

	return result
}
