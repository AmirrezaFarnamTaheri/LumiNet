package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type PhishingResponse struct {
	Match bool `json:"match"`
}

type PhishingVerifier struct {
	mu       sync.RWMutex
	cache    map[string]phishCacheEntry
	client   *http.Client
	checkURL string
}

type phishCacheEntry struct {
	isMalicious bool
	expiry      time.Time
}

var (
	globalPhishingVerifier *PhishingVerifier
	globalPhishingOnce     sync.Once
)

func GetPhishingVerifier() *PhishingVerifier {
	globalPhishingOnce.Do(func() {
		globalPhishingVerifier = &PhishingVerifier{
			cache:    make(map[string]phishCacheEntry),
			client:   &http.Client{Timeout: 3 * time.Second},
			checkURL: "https://api.phish.gg/domain", // generic endpoint lookup
		}
	})
	return globalPhishingVerifier
}

// SetCheckURL allows overriding target check URL in testing
func (v *PhishingVerifier) SetCheckURL(url string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.checkURL = url
}

// IsMalicious checks a target domain against the phish.gg API with local memory cache
func (v *PhishingVerifier) IsMalicious(ctx context.Context, domain string) (bool, error) {
	v.mu.RLock()
	entry, found := v.cache[domain]
	v.mu.RUnlock()

	if found && time.Now().Before(entry.expiry) {
		return entry.isMalicious, nil
	}

	// Dynamic API check
	reqURL, err := url.Parse(v.checkURL)
	if err != nil {
		return false, err
	}

	query := reqURL.Query()
	query.Set("domain", domain)
	reqURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL.String(), nil)
	if err != nil {
		return false, err
	}

	resp, err := v.client.Do(req)
	if err != nil {
		// Log error and fail open to avoid breaking connection flows on connection drop
		return false, fmt.Errorf("phishing api unavailable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("phishing api returned HTTP error: %d", resp.StatusCode)
	}

	var payload PhishingResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false, err
	}

	v.mu.Lock()
	v.cache[domain] = phishCacheEntry{
		isMalicious: payload.Match,
		expiry:      time.Now().Add(10 * time.Minute), // Cache outcomes for 10 minutes
	}
	v.mu.Unlock()

	return payload.Match, nil
}
