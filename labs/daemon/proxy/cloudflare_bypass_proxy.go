// Package proxy implements proxy server handlers and protocol parsers.
// Ported from: cloudflare-bypass-main (cfproxy.py + worker.js)
// Target path: server/internal/proxy/cloudflare_bypass_proxy.go

package proxy

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// CloudflareBypassProxy manages request obfuscation and reverse proxy headers forwarding.
type CloudflareBypassProxy struct {
	mu           sync.RWMutex
	ProxyHost    string
	UserAgent    string
	FakeIP       string
	TokenValue   string
	HostHeader   string
	TokenHeader  string
	IpHeader     string
	OriginUrl    string
	Timeout      time.Duration
	DebugEnabled bool
	IsActive     bool
	MaxRedirects int
}

// Getters & Setters for CloudflareBypassProxy
func (p *CloudflareBypassProxy) GetProxyHost() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.ProxyHost
}
func (p *CloudflareBypassProxy) SetProxyHost(v string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ProxyHost = v
}
func (p *CloudflareBypassProxy) GetUserAgent() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.UserAgent
}
func (p *CloudflareBypassProxy) SetUserAgent(v string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.UserAgent = v
}
func (p *CloudflareBypassProxy) GetFakeIP() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.FakeIP
}
func (p *CloudflareBypassProxy) SetFakeIP(v string) { p.mu.Lock(); defer p.mu.Unlock(); p.FakeIP = v }
func (p *CloudflareBypassProxy) GetTokenValue() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.TokenValue
}
func (p *CloudflareBypassProxy) SetTokenValue(v string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.TokenValue = v
}
func (p *CloudflareBypassProxy) GetHostHeader() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.HostHeader
}
func (p *CloudflareBypassProxy) SetHostHeader(v string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.HostHeader = v
}
func (p *CloudflareBypassProxy) GetTokenHeader() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.TokenHeader
}
func (p *CloudflareBypassProxy) SetTokenHeader(v string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.TokenHeader = v
}
func (p *CloudflareBypassProxy) GetIpHeader() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.IpHeader
}
func (p *CloudflareBypassProxy) SetIpHeader(v string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.IpHeader = v
}
func (p *CloudflareBypassProxy) GetOriginUrl() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.OriginUrl
}
func (p *CloudflareBypassProxy) SetOriginUrl(v string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.OriginUrl = v
}
func (p *CloudflareBypassProxy) GetTimeout() time.Duration {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.Timeout
}
func (p *CloudflareBypassProxy) SetTimeout(v time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Timeout = v
}
func (p *CloudflareBypassProxy) GetDebugEnabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.DebugEnabled
}
func (p *CloudflareBypassProxy) SetDebugEnabled(v bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.DebugEnabled = v
}
func (p *CloudflareBypassProxy) GetIsActive() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.IsActive
}
func (p *CloudflareBypassProxy) SetIsActive(v bool) { p.mu.Lock(); defer p.mu.Unlock(); p.IsActive = v }
func (p *CloudflareBypassProxy) GetMaxRedirects() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.MaxRedirects
}
func (p *CloudflareBypassProxy) SetMaxRedirects(v int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.MaxRedirects = v
}

// Builders for CloudflareBypassProxy
func (p *CloudflareBypassProxy) WithProxyHost(v string) *CloudflareBypassProxy {
	p.SetProxyHost(v)
	return p
}
func (p *CloudflareBypassProxy) WithUserAgent(v string) *CloudflareBypassProxy {
	p.SetUserAgent(v)
	return p
}
func (p *CloudflareBypassProxy) WithFakeIP(v string) *CloudflareBypassProxy { p.SetFakeIP(v); return p }
func (p *CloudflareBypassProxy) WithTokenValue(v string) *CloudflareBypassProxy {
	p.SetTokenValue(v)
	return p
}
func (p *CloudflareBypassProxy) WithHostHeader(v string) *CloudflareBypassProxy {
	p.SetHostHeader(v)
	return p
}
func (p *CloudflareBypassProxy) WithTokenHeader(v string) *CloudflareBypassProxy {
	p.SetTokenHeader(v)
	return p
}
func (p *CloudflareBypassProxy) WithIpHeader(v string) *CloudflareBypassProxy {
	p.SetIpHeader(v)
	return p
}
func (p *CloudflareBypassProxy) WithOriginUrl(v string) *CloudflareBypassProxy {
	p.SetOriginUrl(v)
	return p
}
func (p *CloudflareBypassProxy) WithTimeout(v time.Duration) *CloudflareBypassProxy {
	p.SetTimeout(v)
	return p
}
func (p *CloudflareBypassProxy) WithDebugEnabled(v bool) *CloudflareBypassProxy {
	p.SetDebugEnabled(v)
	return p
}
func (p *CloudflareBypassProxy) WithIsActive(v bool) *CloudflareBypassProxy {
	p.SetIsActive(v)
	return p
}
func (p *CloudflareBypassProxy) WithMaxRedirects(v int) *CloudflareBypassProxy {
	p.SetMaxRedirects(v)
	return p
}

// Operations
func NewCloudflareBypassProxy() *CloudflareBypassProxy {
	return &CloudflareBypassProxy{
		TokenHeader: "Px-Token",
		TokenValue:  "mysecuretoken",
		HostHeader:  "Px-Host",
		IpHeader:    "Px-IP",
		Timeout:     5 * time.Second,
		IsActive:    true,
	}
}

func (p *CloudflareBypassProxy) CreateBypassRequest(ctx context.Context, method, targetUrl string) (*http.Request, error) {
	parsed, err := url.Parse(targetUrl)
	if err != nil {
		return nil, err
	}

	proxyfied := &url.URL{
		Scheme: parsed.Scheme,
		Host:   p.GetProxyHost(),
		Path:   parsed.Path,
	}

	req, err := http.NewRequestWithContext(ctx, method, proxyfied.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", p.GetUserAgent())
	req.Header.Set(p.GetTokenHeader(), p.GetTokenValue())
	req.Header.Set(p.GetHostHeader(), parsed.Hostname())
	req.Header.Set(p.GetIpHeader(), p.GetFakeIP())

	return req, nil
}

func (p *CloudflareBypassProxy) ProcessBypassResponse(resp *http.Response) {
	if resp == nil {
		return
	}
	// Sanitize custom headers from response
	resp.Header.Del(p.GetTokenHeader())
	resp.Header.Del(p.GetHostHeader())
	resp.Header.Del(p.GetIpHeader())
}

func (p *CloudflareBypassProxy) ValidateBypassToken(req *http.Request) bool {
	return req.Header.Get(p.GetTokenHeader()) == p.GetTokenValue()
}

func (p *CloudflareBypassProxy) CleanRequestHeaders(req *http.Request) {
	for k := range req.Header {
		lower := strings.ToLower(k)
		if lower == strings.ToLower(p.GetTokenHeader()) ||
			lower == strings.ToLower(p.GetHostHeader()) ||
			lower == strings.ToLower(p.GetIpHeader()) ||
			strings.HasPrefix(lower, "cf-") ||
			lower == "x-forwarded-for" ||
			lower == "x-real-ip" {
			req.Header.Del(k)
		}
	}
	req.Header.Set("Host", req.Header.Get(p.GetHostHeader()))
	req.Header.Set("X-Forwarded-For", req.Header.Get(p.GetIpHeader()))
}

func (p *CloudflareBypassProxy) ExecuteBypassRoundTrip(client *http.Client, req *http.Request) (*http.Response, error) {
	p.CleanRequestHeaders(req)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	p.ProcessBypassResponse(resp)
	return resp, nil
}

func (p *CloudflareBypassProxy) ExportCurlCommand(method, targetUrl string) string {
	parsed, _ := url.Parse(targetUrl)
	return "curl -H \"" + p.GetTokenHeader() + ": " + p.GetTokenValue() + "\" -H \"" + p.GetHostHeader() + ": " + parsed.Hostname() + "\" -H \"" + p.GetIpHeader() + ": " + p.GetFakeIP() + "\" " + targetUrl
}

// Added SessionProxy options matching upstream cfproxy.py constructor options
type CloudflareProxySettings struct {
	mu           sync.RWMutex
	ProxyURL     string
	HttpProxy    string
	HttpsProxy   string
	BypassActive bool
}

// Getters & Setters
func (s *CloudflareProxySettings) GetProxyURL() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ProxyURL
}
func (s *CloudflareProxySettings) SetProxyURL(v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ProxyURL = v
}
func (s *CloudflareProxySettings) GetHttpProxy() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.HttpProxy
}
func (s *CloudflareProxySettings) SetHttpProxy(v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.HttpProxy = v
}
func (s *CloudflareProxySettings) GetHttpsProxy() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.HttpsProxy
}
func (s *CloudflareProxySettings) SetHttpsProxy(v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.HttpsProxy = v
}
func (s *CloudflareProxySettings) GetBypassActive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.BypassActive
}
func (s *CloudflareProxySettings) SetBypassActive(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.BypassActive = v
}

// Builders
func (s *CloudflareProxySettings) WithProxyURL(v string) *CloudflareProxySettings {
	s.SetProxyURL(v)
	return s
}
func (s *CloudflareProxySettings) WithHttpProxy(v string) *CloudflareProxySettings {
	s.SetHttpProxy(v)
	return s
}
func (s *CloudflareProxySettings) WithHttpsProxy(v string) *CloudflareProxySettings {
	s.SetHttpsProxy(v)
	return s
}
func (s *CloudflareProxySettings) WithBypassActive(v bool) *CloudflareProxySettings {
	s.SetBypassActive(v)
	return s
}

func NewCloudflareProxySettings() *CloudflareProxySettings {
	return &CloudflareProxySettings{
		BypassActive: true,
	}
}

func (s *CloudflareProxySettings) ConfigureTransport(transport *http.Transport) error {
	if s.GetProxyURL() == "" {
		return nil
	}
	parsed, err := url.Parse(s.GetProxyURL())
	if err != nil {
		return err
	}
	transport.Proxy = http.ProxyURL(parsed)
	return nil
}
