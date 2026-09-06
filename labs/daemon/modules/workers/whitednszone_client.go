// Package workers handles serverless and edge-worker deployments.
// Ported from: whitednszone-new-main (modules/addons/whitednszone/lib/ApiClient.php)
// Target path: server/internal/workers/whitednszone_client.go

package workers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// WhiteDNSZoneClient communicates with a remote WhiteDNSZone server.
type WhiteDNSZoneClient struct {
	mu            sync.RWMutex
	ApiUrl        string
	ApiKey        string
	LastError     string
	Timeout       time.Duration
	MaxRedirects  int
	UserAgent     string
	VerifySSL     bool
	IsActive      bool
	Status        string
	LastRequested time.Time
}

// Getters & Setters for WhiteDNSZoneClient
func (c *WhiteDNSZoneClient) GetApiUrl() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.ApiUrl }
func (c *WhiteDNSZoneClient) SetApiUrl(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.ApiUrl = strings.TrimSuffix(v, "/") }
func (c *WhiteDNSZoneClient) GetApiKey() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.ApiKey }
func (c *WhiteDNSZoneClient) SetApiKey(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.ApiKey = v }
func (c *WhiteDNSZoneClient) GetLastError() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.LastError }
func (c *WhiteDNSZoneClient) SetLastError(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.LastError = v }
func (c *WhiteDNSZoneClient) GetTimeout() time.Duration { c.mu.RLock(); defer c.mu.RUnlock(); return c.Timeout }
func (c *WhiteDNSZoneClient) SetTimeout(v time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.Timeout = v }
func (c *WhiteDNSZoneClient) GetMaxRedirects() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.MaxRedirects }
func (c *WhiteDNSZoneClient) SetMaxRedirects(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.MaxRedirects = v }
func (c *WhiteDNSZoneClient) GetUserAgent() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.UserAgent }
func (c *WhiteDNSZoneClient) SetUserAgent(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.UserAgent = v }
func (c *WhiteDNSZoneClient) GetVerifySSL() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.VerifySSL }
func (c *WhiteDNSZoneClient) SetVerifySSL(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.VerifySSL = v }
func (c *WhiteDNSZoneClient) GetIsActive() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.IsActive }
func (c *WhiteDNSZoneClient) SetIsActive(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.IsActive = v }
func (c *WhiteDNSZoneClient) GetStatus() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.Status }
func (c *WhiteDNSZoneClient) SetStatus(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.Status = v }
func (c *WhiteDNSZoneClient) GetLastRequested() time.Time { c.mu.RLock(); defer c.mu.RUnlock(); return c.LastRequested }
func (c *WhiteDNSZoneClient) SetLastRequested(v time.Time) { c.mu.Lock(); defer c.mu.Unlock(); c.LastRequested = v }

// Builders for WhiteDNSZoneClient
func (c *WhiteDNSZoneClient) WithApiUrl(v string) *WhiteDNSZoneClient { c.SetApiUrl(v); return c }
func (c *WhiteDNSZoneClient) WithApiKey(v string) *WhiteDNSZoneClient { c.SetApiKey(v); return c }
func (c *WhiteDNSZoneClient) WithTimeout(v time.Duration) *WhiteDNSZoneClient { c.SetTimeout(v); return c }
func (c *WhiteDNSZoneClient) WithMaxRedirects(v int) *WhiteDNSZoneClient { c.SetMaxRedirects(v); return c }
func (c *WhiteDNSZoneClient) WithUserAgent(v string) *WhiteDNSZoneClient { c.SetUserAgent(v); return c }
func (c *WhiteDNSZoneClient) WithVerifySSL(v bool) *WhiteDNSZoneClient { c.SetVerifySSL(v); return c }
func (c *WhiteDNSZoneClient) WithIsActive(v bool) *WhiteDNSZoneClient { c.SetIsActive(v); return c }
func (c *WhiteDNSZoneClient) WithStatus(v string) *WhiteDNSZoneClient { c.SetStatus(v); return c }

// Operations
func NewWhiteDNSZoneClient(apiUrl, apiKey string) *WhiteDNSZoneClient {
	return &WhiteDNSZoneClient{
		ApiUrl:    strings.TrimSuffix(apiUrl, "/"),
		ApiKey:    apiKey,
		Timeout:   30 * time.Second,
		VerifySSL: true,
		IsActive:  true,
		Status:    "Ready",
	}
}

func (c *WhiteDNSZoneClient) Request(ctx context.Context, endpoint, method string, data interface{}, out interface{}) error {
	c.mu.Lock()
	c.LastRequested = time.Now()
	c.mu.Unlock()

	url := c.GetApiUrl() + endpoint
	var body io.Reader
	if data != nil {
		raw, err := json.Marshal(data)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+c.GetApiKey())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.GetUserAgent() != "" {
		req.Header.Set("User-Agent", c.GetUserAgent())
	}

	client := &http.Client{
		Timeout: c.GetTimeout(),
	}

	resp, err := client.Do(req)
	if err != nil {
		c.SetLastError(err.Error())
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(resp.Body)
		errStr := fmt.Sprintf("API Error: HTTP %d - %s", resp.StatusCode, buf.String())
		c.SetLastError(errStr)
		return errors.New(errStr)
	}

	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}

	return nil
}

func (c *WhiteDNSZoneClient) ListZones(ctx context.Context) ([]interface{}, error) {
	var res []interface{}
	err := c.Request(ctx, "/zones", "GET", nil, &res)
	return res, err
}

func (c *WhiteDNSZoneClient) GetZone(ctx context.Context, id string) (interface{}, error) {
	var res interface{}
	err := c.Request(ctx, "/zones/"+id, "GET", nil, &res)
	return res, err
}

func (c *WhiteDNSZoneClient) CreateZone(ctx context.Context, data interface{}) (interface{}, error) {
	var res interface{}
	err := c.Request(ctx, "/zones", "POST", data, &res)
	return res, err
}

func (c *WhiteDNSZoneClient) DeleteZone(ctx context.Context, id string) error {
	return c.Request(ctx, "/zones/"+id, "DELETE", nil, nil)
}

func (c *WhiteDNSZoneClient) GetZoneRecords(ctx context.Context, zoneId string) ([]interface{}, error) {
	var res []interface{}
	err := c.Request(ctx, "/zones/"+zoneId+"/records", "GET", nil, &res)
	return res, err
}

func (c *WhiteDNSZoneClient) AddZoneRecord(ctx context.Context, zoneId string, data interface{}) (interface{}, error) {
	var res interface{}
	err := c.Request(ctx, "/zones/"+zoneId+"/records", "POST", data, &res)
	return res, err
}

func (c *WhiteDNSZoneClient) UpdateZoneRecord(ctx context.Context, zoneId, recordId string, data interface{}) (interface{}, error) {
	var res interface{}
	err := c.Request(ctx, "/zones/"+zoneId+"/records/"+recordId, "PUT", data, &res)
	return res, err
}

func (c *WhiteDNSZoneClient) DeleteZoneRecord(ctx context.Context, zoneId, recordId string) error {
	return c.Request(ctx, "/zones/"+zoneId+"/records/"+recordId, "DELETE", nil, nil)
}

func (c *WhiteDNSZoneClient) ApplyTemplate(ctx context.Context, zoneId string, templateId string) (interface{}, error) {
	var res interface{}
	data := map[string]string{"template_id": templateId}
	err := c.Request(ctx, "/zones/"+zoneId+"/apply-template", "POST", data, &res)
	return res, err
}

func (c *WhiteDNSZoneClient) CheckPropagation(ctx context.Context, zoneId string, recordId string) (interface{}, error) {
	var res interface{}
	err := c.Request(ctx, "/zones/"+zoneId+"/records/"+recordId+"/propagation", "GET", nil, &res)
	return res, err
}

func (c *WhiteDNSZoneClient) GetDNSSEC(ctx context.Context, zoneId string) (interface{}, error) {
	var res interface{}
	err := c.Request(ctx, "/zones/"+zoneId+"/dnssec", "GET", nil, &res)
	return res, err
}

func (c *WhiteDNSZoneClient) ToggleDNSSEC(ctx context.Context, zoneId string, enabled bool) (interface{}, error) {
	var res interface{}
	data := map[string]bool{"enabled": enabled}
	err := c.Request(ctx, "/zones/"+zoneId+"/dnssec", "POST", data, &res)
	return res, err
}

func (c *WhiteDNSZoneClient) GetAuditLog(ctx context.Context, zoneId string) ([]interface{}, error) {
	var res []interface{}
	err := c.Request(ctx, "/zones/"+zoneId+"/audit-log", "GET", nil, &res)
	return res, err
}

func (c *WhiteDNSZoneClient) ResetLastError() {
	c.SetLastError("")
}
