package updateadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const maxDiscoveryResponseBytes int64 = 96 << 10

// Discover fetches a signed update Envelope from an HTTPS URL. It does not
// verify the envelope's signature; callers must pass the result to Verifier.
func Discover(ctx context.Context, client *http.Client, rawURL string) (Envelope, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	candidate, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return Envelope{}, fmt.Errorf("parse update manifest URL: %w", err)
	}
	if err := validateUpdateURL(candidate); err != nil {
		return Envelope{}, err
	}
	boundedClient, err := boundedUpdateHTTPClient(client)
	if err != nil {
		return Envelope{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, candidate.String(), nil)
	if err != nil {
		return Envelope{}, fmt.Errorf("build update manifest request: %w", err)
	}
	resp, err := boundedClient.Do(req)
	if err != nil {
		return Envelope{}, fmt.Errorf("download update manifest: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Envelope{}, fmt.Errorf("download update manifest: HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxDiscoveryResponseBytes {
		return Envelope{}, fmt.Errorf("update manifest response exceeds %d bytes", maxDiscoveryResponseBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryResponseBytes+1))
	if err != nil {
		return Envelope{}, fmt.Errorf("read update manifest: %w", err)
	}
	if int64(len(body)) > maxDiscoveryResponseBytes {
		return Envelope{}, fmt.Errorf("update manifest response exceeds %d bytes", maxDiscoveryResponseBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var envelope Envelope
	if err := dec.Decode(&envelope); err != nil {
		return Envelope{}, fmt.Errorf("decode update manifest envelope: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Envelope{}, errors.New("update manifest response contains trailing JSON values")
	}
	if strings.TrimSpace(envelope.KeyID) == "" || strings.TrimSpace(envelope.Payload) == "" || strings.TrimSpace(envelope.Signature) == "" {
		return Envelope{}, errors.New("update manifest envelope requires key_id, payload, and signature")
	}
	return envelope, nil
}
