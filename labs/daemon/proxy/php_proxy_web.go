// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: php-proxy-app-master
// Target path: server/internal/proxy/php_proxy_web.go

package proxy

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// PHPProxyWeb implements URL encryption/decryption and HTML links rewriting rules.
type PHPProxyWeb struct {
	mu      sync.RWMutex
	AppKey  string
	URLMode int // 1: Base64 only, 2: IP-bound Hash, 3: Session-bound
}

// NewPHPProxyWeb instantiates a PHPProxyWeb.
func NewPHPProxyWeb(appKey string, mode int) *PHPProxyWeb {
	return &PHPProxyWeb{
		AppKey:  appKey,
		URLMode: mode,
	}
}

// 1. GetEncryptionKey derives the encryption key based on URLMode.
func (p *PHPProxyWeb) GetEncryptionKey(clientIP string) string {
	p.mu.RLock()
	key := p.AppKey
	mode := p.URLMode
	p.mu.RUnlock()

	if mode == 2 {
		h := md5.New()
		h.Write([]byte(key + clientIP))
		return hex.EncodeToString(h.Sum(nil))
	}
	return key
}

// 2. EncryptURL encodes/encrypts target URL to hide destination.
func (p *PHPProxyWeb) EncryptURL(urlStr string, clientIP string) string {
	p.mu.RLock()
	mode := p.URLMode
	p.mu.RUnlock()

	if mode == 0 {
		return urlStr
	}

	raw := []byte(urlStr)
	if mode == 1 {
		return base64.StdEncoding.EncodeToString(raw)
	}

	key := p.GetEncryptionKey(clientIP)
	encrypted := make([]byte, len(raw))
	for i := 0; i < len(raw); i++ {
		encrypted[i] = raw[i] ^ key[i%len(key)]
	}

	return base64.StdEncoding.EncodeToString(encrypted)
}

// 3. DecryptURL decodes/decrypts the encoded parameter string.
func (p *PHPProxyWeb) DecryptURL(encryptedStr string, clientIP string) (string, error) {
	p.mu.RLock()
	mode := p.URLMode
	p.mu.RUnlock()

	if mode == 0 {
		return encryptedStr, nil
	}

	raw, err := base64.StdEncoding.DecodeString(encryptedStr)
	if err != nil {
		return "", err
	}

	if mode == 1 {
		return string(raw), nil
	}

	key := p.GetEncryptionKey(clientIP)
	decrypted := make([]byte, len(raw))
	for i := 0; i < len(raw); i++ {
		decrypted[i] = raw[i] ^ key[i%len(key)]
	}

	return string(decrypted), nil
}

// 4. ServeHTTP acts as the HTTP Reverse Proxy that decrypts, fetches, and rewrites HTML links.
func (p *PHPProxyWeb) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if q == "" {
		http.Error(w, "Query parameter q is required", http.StatusBadRequest)
		return
	}

	clientIP := strings.Split(r.RemoteAddr, ":")[0]

	targetURL, err := p.DecryptURL(q, clientIP)
	if err != nil {
		http.Error(w, "Failed to decrypt URL", http.StatusBadRequest)
		return
	}

	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch target: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response body", http.StatusInternalServerError)
		return
	}

	bodyStr := string(bodyBytes)

	originURL, _ := url.Parse(targetURL)
	if originURL != nil {
		bodyStr = strings.ReplaceAll(bodyStr, originURL.Host, r.Host)
	}

	re := regexp.MustCompile(`(href|src|action)=["'](http[^"']+)["']`)
	rewritten := re.ReplaceAllStringFunc(bodyStr, func(m string) string {
		sub := re.FindStringSubmatch(m)
		if len(sub) < 3 {
			return m
		}
		attr := sub[1]
		val := sub[2]
		enc := p.EncryptURL(val, clientIP)
		return fmt.Sprintf(`%s="/proxy?q=%s"`, attr, enc)
	})

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write([]byte(rewritten))
}

// 5. SetAppKey configures the application key.
func (p *PHPProxyWeb) SetAppKey(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.AppKey = key
}

// 6. GetAppKey returns the application key.
func (p *PHPProxyWeb) GetAppKey() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.AppKey
}

// 7. SetURLMode configures the decryption mode setting.
func (p *PHPProxyWeb) SetURLMode(mode int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.URLMode = mode
}

// 8. GetURLMode returns the active decryption mode setting.
func (p *PHPProxyWeb) GetURLMode() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.URLMode
}

// 9. RemoveHTMLTargetScripts strips JS script blocks from HTML payload.
func (p *PHPProxyWeb) RemoveHTMLTargetScripts(html string) string {
	re := regexp.MustCompile(`(?s)<script.*?>.*?</script>`)
	return re.ReplaceAllString(html, "")
}

// 10. ObfuscateCookieHeaders strips tracking domains cookies.
func (p *PHPProxyWeb) ObfuscateCookieHeaders(req *http.Request) {
	if req != nil {
		req.Header.Del("Cookie")
	}
}

// 11. AddProxyUserAgent configures client agent headers.
func (p *PHPProxyWeb) AddProxyUserAgent(req *http.Request, ua string) {
	if req != nil {
		req.Header.Set("User-Agent", ua)
	}
}

// 12. CleanResponseHeaders removes security policies.
func (p *PHPProxyWeb) CleanResponseHeaders(resp *http.Response) {
	if resp != nil {
		resp.Header.Del("Content-Security-Policy")
		resp.Header.Del("X-Frame-Options")
	}
}

// 13. IsValidTargetURL validates protocol schemes.
func (p *PHPProxyWeb) IsValidTargetURL(target string) bool {
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

// 14. ObfuscateHeaders scrubs reverse proxy metadata footprints.
func (p *PHPProxyWeb) ObfuscateHeaders(w http.ResponseWriter) {
	w.Header().Set("Server", "Apache")
	w.Header().Del("X-Powered-By")
}

// 15. GetHostname parses domains from URL string.
func (p *PHPProxyWeb) GetHostname(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
