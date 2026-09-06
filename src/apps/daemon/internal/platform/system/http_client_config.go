package system

import (
	"crypto/tls"
	"net/http"
	"time"
)

// HttpClientConfig holds timeout and TLS configuration for a plain HTTP client.
type HttpClientConfig struct {
	ConnectTimeout     time.Duration
	ReadTimeout        time.Duration
	WriteTimeout       time.Duration
	MaxIdleConns       int
	IdleConnTimeout    time.Duration
	InsecureSkipVerify bool
}

// NewHttpClientConfig returns a default HttpClientConfig with sensible defaults.
func NewHttpClientConfig() *HttpClientConfig {
	return &HttpClientConfig{
		ConnectTimeout:     30 * time.Second,
		ReadTimeout:        30 * time.Second,
		WriteTimeout:       30 * time.Second,
		MaxIdleConns:       100,
		IdleConnTimeout:    90 * time.Second,
		InsecureSkipVerify: false,
	}
}

// Build creates an *http.Client using the configuration values.
func (c *HttpClientConfig) Build() *http.Client {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: c.InsecureSkipVerify},
		MaxIdleConns:        c.MaxIdleConns,
		IdleConnTimeout:     c.IdleConnTimeout,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &http.Client{
		Timeout:   c.ConnectTimeout + c.ReadTimeout,
		Transport: transport,
	}
}

// HTTPClientConfig is the richer HTTP client configuration used by HTTPClientManager.
type HTTPClientConfig struct {
	TimeoutSeconds int
	BaseURL        string
	Headers        map[string]string
}

// HTTPClientManager wraps an http.Client with base URL and header injection.
type HTTPClientManager struct {
	Config *HTTPClientConfig
	client *http.Client
}

// NewHTTPClientManager creates an HTTPClientManager from the given HTTPClientConfig.
func NewHTTPClientManager(cfg *HTTPClientConfig) *HTTPClientManager {
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: false},
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &HTTPClientManager{
		Config: cfg,
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
	}
}
