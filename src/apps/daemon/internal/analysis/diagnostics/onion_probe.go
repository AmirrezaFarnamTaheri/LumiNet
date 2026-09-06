package diagnostics

import (
	"context"
	"crypto/sha256"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const maxOnionProbeBodyBytes int64 = 64 << 10

var onionV3Label = regexp.MustCompile(`^[a-z2-7]{56}$`)

type OnionProbeResult struct {
	URL              string  `json:"url"`
	OnionHost        string  `json:"onion_host"`
	Proxy            string  `json:"proxy"`
	StatusCode       int     `json:"status_code"`
	LatencyMs        float64 `json:"latency_ms"`
	ContentType      string  `json:"content_type,omitempty"`
	SampleBytes      int     `json:"sample_bytes"`
	TextSample       string  `json:"text_sample,omitempty"`
	Title            string  `json:"title,omitempty"`
	Description      string  `json:"description,omitempty"`
	OnionLinks       int     `json:"onion_links,omitempty"`
	SameServiceLinks int     `json:"same_service_links,omitempty"`
}

func ValidOnionV3Host(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	parts := strings.Split(host, ".")
	if len(parts) < 2 || parts[len(parts)-1] != "onion" {
		return false
	}
	return onionV3Label.MatchString(parts[len(parts)-2])
}

func StableProxyForOnion(host string, endpoints []string) (string, error) {
	if !ValidOnionV3Host(host) {
		return "", fmt.Errorf("invalid v3 onion host")
	}
	clean := make([]string, 0, len(endpoints))
	seen := map[string]struct{}{}
	for _, endpoint := range endpoints {
		e := strings.TrimSpace(endpoint)
		if e == "" {
			continue
		}
		if !strings.Contains(e, "://") {
			e = "socks5://" + e
		}
		u, err := url.Parse(e)
		if err != nil || u.Scheme != "socks5" || u.Host == "" {
			return "", fmt.Errorf("invalid SOCKS5 endpoint %q", endpoint)
		}
		e = u.String()
		if _, ok := seen[e]; ok {
			continue
		}
		seen[e] = struct{}{}
		clean = append(clean, e)
	}
	if len(clean) == 0 {
		return "", fmt.Errorf("at least one SOCKS5 endpoint is required")
	}
	h := sha256.Sum256([]byte(strings.ToLower(host)))
	idx := (uint64(h[0])<<56 | uint64(h[1])<<48 | uint64(h[2])<<40 | uint64(h[3])<<32 | uint64(h[4])<<24 | uint64(h[5])<<16 | uint64(h[6])<<8 | uint64(h[7])) % uint64(len(clean))
	return clean[idx], nil
}

func ProbeOnion(ctx context.Context, rawURL string, endpoints []string, timeout time.Duration) (OnionProbeResult, error) {
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !ValidOnionV3Host(u.Hostname()) {
		return OnionProbeResult{}, fmt.Errorf("probe URL must be http(s) v3 onion")
	}
	proxyURL, err := StableProxyForOnion(u.Hostname(), endpoints)
	if err != nil {
		return OnionProbeResult{}, err
	}
	pu, _ := url.Parse(proxyURL)
	transport := &http.Transport{Proxy: http.ProxyURL(pu), ForceAttemptHTTP2: false, ResponseHeaderTimeout: timeout, TLSHandshakeTimeout: timeout, IdleConnTimeout: timeout}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("too many redirects")
		}
		if !ValidOnionV3Host(req.URL.Hostname()) || !strings.EqualFold(req.URL.Hostname(), u.Hostname()) {
			return fmt.Errorf("cross-onion redirect refused")
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return OnionProbeResult{}, err
	}
	req.Header.Set("User-Agent", "LumiNet-OnionProbe/1")
	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start).Seconds() * 1000
	if err != nil {
		return OnionProbeResult{URL: u.String(), OnionHost: u.Hostname(), Proxy: proxyURL, LatencyMs: latency}, err
	}
	defer resp.Body.Close()
	result := OnionProbeResult{URL: u.String(), OnionHost: u.Hostname(), Proxy: proxyURL, StatusCode: resp.StatusCode, LatencyMs: latency, ContentType: resp.Header.Get("Content-Type")}
	if !strings.HasPrefix(strings.ToLower(result.ContentType), "text/") {
		return result, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOnionProbeBodyBytes+1))
	if err != nil {
		return result, err
	}
	if int64(len(body)) > maxOnionProbeBodyBytes {
		return result, fmt.Errorf("onion response text sample exceeds %d bytes", maxOnionProbeBodyBytes)
	}
	result.SampleBytes = len(body)
	result.TextSample = string(body)
	if strings.Contains(strings.ToLower(result.ContentType), "html") {
		result.Title, result.Description, result.OnionLinks, result.SameServiceLinks = extractOnionHTMLMetadata(body, u)
	}
	return result, nil
}

const maxOnionMetadataLinks = 1000

var (
	titleTagPattern  = regexp.MustCompile(`(?is)<title\b[^>]*>(.*?)</title\s*>`)
	metaTagPattern   = regexp.MustCompile(`(?is)<meta\b[^>]*>`)
	anchorTagPattern = regexp.MustCompile(`(?is)<a\b[^>]*>`)
	htmlAttrPattern  = regexp.MustCompile(`(?i)([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	htmlTagsPattern  = regexp.MustCompile(`(?s)<[^>]*>`)
)

func extractOnionHTMLMetadata(body []byte, base *url.URL) (title, description string, onionLinks, sameServiceLinks int) {
	text := string(body)
	if match := titleTagPattern.FindStringSubmatch(text); len(match) == 2 {
		title = compactHTMLText(match[1], 256)
	}
	for _, tag := range metaTagPattern.FindAllString(text, -1) {
		attrs := parseHTMLAttributes(tag)
		if description == "" && strings.EqualFold(strings.TrimSpace(attrs["name"]), "description") {
			description = compactHTMLText(attrs["content"], 512)
		}
	}
	links := anchorTagPattern.FindAllString(text, maxOnionMetadataLinks)
	for _, tag := range links {
		href := strings.TrimSpace(parseHTMLAttributes(tag)["href"])
		if href == "" {
			continue
		}
		ref, err := url.Parse(html.UnescapeString(href))
		if err != nil {
			continue
		}
		resolved := base.ResolveReference(ref)
		host := strings.ToLower(resolved.Hostname())
		if ValidOnionV3Host(host) {
			onionLinks++
			if strings.EqualFold(host, base.Hostname()) {
				sameServiceLinks++
			}
		}
	}
	return title, description, onionLinks, sameServiceLinks
}

func parseHTMLAttributes(tag string) map[string]string {
	attrs := make(map[string]string)
	for _, match := range htmlAttrPattern.FindAllStringSubmatch(tag, -1) {
		value := match[2]
		if value == "" {
			value = match[3]
		}
		if value == "" {
			value = match[4]
		}
		attrs[strings.ToLower(match[1])] = html.UnescapeString(value)
	}
	return attrs
}

func compactHTMLText(value string, maxBytes int) string {
	value = html.UnescapeString(htmlTagsPattern.ReplaceAllString(value, " "))
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > maxBytes {
		value = value[:maxBytes]
	}
	return value
}
