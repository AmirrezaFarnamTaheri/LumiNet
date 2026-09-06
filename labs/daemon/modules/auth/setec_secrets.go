package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SetecClient queries keys securely from an external Setec secret agent.
type SetecClient struct {
	serverURL   string
	clientToken string
	httpClient  *http.Client
	cache       map[string]cachedSecret
	mu          sync.RWMutex
}

type cachedSecret struct {
	value     string
	expiredAt time.Time
}

type setecResponse struct {
	Value string `json:"value"`
	TTL   int    `json:"ttl"` // in seconds
}

// NewSetecClient creates a new SetecClient.
func NewSetecClient(serverURL, clientToken string) *SetecClient {
	return &SetecClient{
		serverURL:   serverURL,
		clientToken: clientToken,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		cache: make(map[string]cachedSecret),
	}
}

// GetSecret retrieves a secret, checking the cache first.
func (c *SetecClient) GetSecret(secretName string) (string, error) {
	c.mu.RLock()
	cached, ok := c.cache[secretName]
	c.mu.RUnlock()

	if ok && time.Now().Before(cached.expiredAt) {
		return cached.value, nil
	}

	// Cache miss or expired, fetch from external agent
	val, ttl, err := c.fetchSecret(secretName)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	c.cache[secretName] = cachedSecret{
		value:     val,
		expiredAt: time.Now().Add(time.Duration(ttl) * time.Second),
	}
	c.mu.Unlock()

	return val, nil
}

func (c *SetecClient) fetchSecret(secretName string) (string, int, error) {
	val, ttl, err := c.fetchSecretTailscale(secretName)
	if err == nil {
		return val, ttl, nil
	}
	return c.fetchSecretGeneric(secretName)
}

func (c *SetecClient) fetchSecretTailscale(secretName string) (string, int, error) {
	url := fmt.Sprintf("%s/api/get", c.serverURL)
	reqBody := fmt.Sprintf(`{"Name":"%s","Version":0}`, secretName)
	req, err := http.NewRequest("POST", url, strings.NewReader(reqBody))
	if err != nil {
		return "", 0, err
	}

	req.Header.Set("Authorization", "Bearer "+c.clientToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return "", 0, errors.New("unauthorized token")
	}
	if resp.StatusCode == http.StatusNotFound {
		return "", 0, fmt.Errorf("secret %q not found", secretName)
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("server error: %s", resp.Status)
	}

	var res struct {
		Value   string `json:"Value"` // base64-encoded bytes or raw string
		Version uint32 `json:"Version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", 0, err
	}

	// Try base64 decoding the value, fallback to raw value if decoding fails
	decoded, err := base64.StdEncoding.DecodeString(res.Value)
	if err == nil {
		return string(decoded), 300, nil // 5 minutes TTL for Tailscale secrets
	}
	return res.Value, 300, nil
}

func (c *SetecClient) fetchSecretGeneric(secretName string) (string, int, error) {
	url := fmt.Sprintf("%s/v1/secrets/%s", c.serverURL, secretName)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", 0, err
	}

	req.Header.Set("Authorization", "Bearer "+c.clientToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return "", 0, errors.New("unauthorized token")
	}
	if resp.StatusCode == http.StatusNotFound {
		return "", 0, fmt.Errorf("secret %q not found", secretName)
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("server error: %s", resp.Status)
	}

	var res setecResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", 0, err
	}

	if res.TTL <= 0 {
		res.TTL = 60 // Default TTL: 60 seconds
	}

	return res.Value, res.TTL, nil
}
