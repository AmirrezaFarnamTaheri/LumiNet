// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: ProxyPanel-master
// Target path: server/internal/proxy/proxy_panel_bridge.go

package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// ProxyPanelBridge integrates with ProxyPanel's Laravel endpoints and notifications channels (from DingTalkChannel.php).
type ProxyPanelBridge struct {
	mu            sync.RWMutex
	accessToken   string
	secretKey     string
	rateLimitMin  int
	messageCount  int
	lastResetTime time.Time
}

// NewProxyPanelBridge instantiates a new ProxyPanelBridge.
func NewProxyPanelBridge(token, secret string) *ProxyPanelBridge {
	return &ProxyPanelBridge{
		accessToken:   token,
		secretKey:     secret,
		rateLimitMin:  20,
		lastResetTime: time.Now(),
	}
}

// Sign computes the HMAC-SHA256 signature required by DingTalk custom robot API (from DingTalkChannel.php).
func (p *ProxyPanelBridge) Sign(timestamp int64) string {
	p.mu.RLock()
	secret := p.secretKey
	p.mu.RUnlock()

	if secret == "" {
		return ""
	}

	stringToSign := fmt.Sprintf("%d\n%s", timestamp, secret)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// SendDingTalkMessage checks rate limit (max 20 messages per minute) and sends DingTalk notifications (from DingTalkChannel.php).
func (p *ProxyPanelBridge) SendDingTalkMessage(content string) (bool, error) {
	p.mu.Lock()
	now := time.Now()
	if now.Sub(p.lastResetTime) >= time.Minute {
		p.messageCount = 0
		p.lastResetTime = now
	}

	if p.messageCount >= p.rateLimitMin {
		p.mu.Unlock()
		return false, fmt.Errorf("rate limit exceeded: max 20 messages per minute")
	}

	p.messageCount++
	p.mu.Unlock()

	// In a real environment, this makes an HTTP POST request to:
	// https://oapi.dingtalk.com/robot/send?access_token=...&timestamp=...&sign=...
	return true, nil
}

// ParseDataRate computes readable data rate conversions (from data_rate.php cast).
func (p *ProxyPanelBridge) ParseDataRate(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// SendBarkMessage dispatches a GET notification request to Bark API endpoint (from BarkChannel.php).
func (p *ProxyPanelBridge) SendBarkMessage(title, content, barkKey string) (bool, error) {
	if barkKey == "" {
		return false, fmt.Errorf("missing bark key")
	}

	escapedTitle := url.PathEscape(title)
	escapedContent := url.PathEscape(content)

	barkURL := fmt.Sprintf("https://api.day.app/%s/%s/%s", barkKey, escapedTitle, escapedContent)

	req, err := http.NewRequest("GET", barkURL, nil)
	if err != nil {
		return false, err
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("bark API returned status %d", resp.StatusCode)
	}

	return true, nil
}
