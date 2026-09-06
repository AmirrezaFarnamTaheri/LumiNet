// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: XHTTPRelayFastly-master
// Target path: server/internal/proxy/xhttp_fastly.go

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

// XHTTPFastly handles the Fastly Compute@Edge Config Store variables and CLI token auth.
type XHTTPFastly struct {
	APIToken  string
	ServiceID string
}

// NewXHTTPFastly instantiates a new XHTTPFastly.
func NewXHTTPFastly() *XHTTPFastly {
	return &XHTTPFastly{
		APIToken:  "default-fastly-token",
		ServiceID: "default-service-id",
	}
}

// ConfigureFastlyStore makes API requests to Fastly's configuration store service to dynamically inject or update variables.
func (x *XHTTPFastly) ConfigureFastlyStore(ctx context.Context, dictionaryID string, key string, value string) error {
	url := fmt.Sprintf("https://api.fastly.com/service/%s/dictionary/%s/item/%s", x.ServiceID, dictionaryID, key)

	payload := map[string]string{
		"item_value": value,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}

	req.Header.Set("Fastly-Key", x.APIToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBytes, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("fastly API returned status %d: %s", resp.StatusCode, string(respBytes))
	}

	log.Printf("XHTTPFastly: Configured key %s on Fastly Config Store Dictionary %s", key, dictionaryID)
	return nil
}

// RunRelay is the legacy diagnostic entry trigger.
func (x *XHTTPFastly) RunRelay() {
	// Diagnostic stub
}
