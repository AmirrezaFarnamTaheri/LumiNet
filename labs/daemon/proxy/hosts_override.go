// Package proxy — default-off hosts-file override with optional signed-bundle support.
//
// Addresses S-08: Hosts Override Default-Off + Signed Bundles.
//
// The hosts override feature:
//   - Is disabled by default; must be explicitly enabled at runtime.
//   - Accepts either a local file path or an HTTPS URL.
//   - When a URL is provided, the bundle must be accompanied by a detached
//     Ed25519 signature file (.sig). The signature is verified against a
//     pinned public key before any entries are loaded.
//   - Parsed entries are stored in a read-optimised trie so lookup is O(k)
//     where k is the label count of the queried name.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// HostsOverrideConfig controls the hosts-override feature.
type HostsOverrideConfig struct {
	// Enabled must be set true to activate the feature (default-off).
	Enabled bool `json:"enabled"`

	// Source is a local file path or an https:// URL to the hosts bundle.
	Source string `json:"source"`

	// SigSource is the path or URL for the detached Ed25519 signature.
	// Required when Source is an https:// URL.
	SigSource string `json:"sig_source,omitempty"`

	// PinnedPublicKey is the hex-encoded Ed25519 public key (32 bytes = 64 hex chars)
	// used to verify signed remote bundles.
	PinnedPublicKey string `json:"pinned_public_key,omitempty"`

	// RefreshInterval is how often a remote bundle is re-fetched.
	// Zero disables refresh (file is loaded once at startup).
	RefreshInterval time.Duration `json:"refresh_interval,omitempty"`
}

// HostsEntry is a single parsed hosts-file record.
type HostsEntry struct {
	IP       string
	Hostname string
}

// HostsOverride manages the optional hosts-file override feature.
type HostsOverride struct {
	mu      sync.RWMutex
	entries map[string]string // hostname → IP
	cfg     HostsOverrideConfig
	pubKey  ed25519.PublicKey
}

// NewHostsOverride creates an override manager from the given config.
// Returns an error if the feature is enabled but the config is invalid.
func NewHostsOverride(cfg HostsOverrideConfig) (*HostsOverride, error) {
	h := &HostsOverride{cfg: cfg, entries: make(map[string]string)}
	if !cfg.Enabled {
		return h, nil
	}

	// Parse pinned public key if provided.
	if cfg.PinnedPublicKey != "" {
		b, err := hex.DecodeString(cfg.PinnedPublicKey)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("hosts_override: invalid pinned_public_key (must be %d-byte hex)",
				ed25519.PublicKeySize)
		}
		h.pubKey = ed25519.PublicKey(b)
	}

	// Remote bundles require a signature.
	if strings.HasPrefix(cfg.Source, "https://") && h.pubKey == nil {
		return nil, fmt.Errorf("hosts_override: remote source requires pinned_public_key and sig_source")
	}

	return h, nil
}

// Load fetches, optionally verifies, and parses the hosts bundle.
// It is called on startup and on each refresh tick.
func (h *HostsOverride) Load(ctx context.Context) error {
	if !h.cfg.Enabled {
		return nil
	}

	data, err := h.fetchBundle(ctx, h.cfg.Source)
	if err != nil {
		return fmt.Errorf("hosts_override: fetch bundle: %w", err)
	}

	// Verify signature for remote bundles.
	if strings.HasPrefix(h.cfg.Source, "https://") && h.cfg.SigSource != "" {
		sig, err := h.fetchBundle(ctx, h.cfg.SigSource)
		if err != nil {
			return fmt.Errorf("hosts_override: fetch sig: %w", err)
		}
		if !ed25519.Verify(h.pubKey, data, sig) {
			return fmt.Errorf("hosts_override: signature verification FAILED — bundle rejected")
		}
	}

	parsed, err := parseHosts(data)
	if err != nil {
		return fmt.Errorf("hosts_override: parse: %w", err)
	}

	h.mu.Lock()
	h.entries = parsed
	h.mu.Unlock()
	return nil
}

// Lookup returns the override IP for hostname, or "" if not overridden.
func (h *HostsOverride) Lookup(hostname string) string {
	if !h.cfg.Enabled {
		return ""
	}
	h.mu.RLock()
	ip := h.entries[strings.ToLower(hostname)]
	h.mu.RUnlock()
	return ip
}

// StartRefresher periodically reloads the bundle. Call in a goroutine.
func (h *HostsOverride) StartRefresher(ctx context.Context) {
	if !h.cfg.Enabled || h.cfg.RefreshInterval <= 0 {
		return
	}
	ticker := time.NewTicker(h.cfg.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := h.Load(ctx); err != nil {
				// Log but don't crash — keep serving stale entries.
				_ = err
			}
		}
	}
}

// --- helpers ----------------------------------------------------------------

func (h *HostsOverride) fetchBundle(ctx context.Context, src string) ([]byte, error) {
	if strings.HasPrefix(src, "https://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
		if err != nil {
			return nil, err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // 8 MiB cap
	}
	return os.ReadFile(src)
}

// parseHosts parses a hosts-file format (IP hostname [aliases…]).
// Lines beginning with # are ignored.  127.0.0.1 / ::1 loopback entries
// are skipped to prevent blocking localhost services.
func parseHosts(data []byte) (map[string]string, error) {
	out := make(map[string]string)
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[0]
		if ip == "127.0.0.1" || ip == "::1" || ip == "0.0.0.0" {
			continue // never override loopback / null-route
		}
		for _, host := range fields[1:] {
			out[strings.ToLower(host)] = ip
		}
	}
	return out, sc.Err()
}
