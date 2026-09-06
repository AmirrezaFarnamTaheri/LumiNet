package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSessionConfigDefaultsAndEnvironmentOverrides(t *testing.T) {
	t.Parallel()

	cfg, err := loadSessionConfig(filepath.Join(t.TempDir(), "missing.json"), func(key string) (string, bool) {
		switch key {
		case "LUMINET_API_URL":
			return "https://control.example.test/root/", true
		case "LUMINET_API_KEY":
			return "environment-key", true
		default:
			return "", false
		}
	})
	if err != nil {
		t.Fatalf("loadSessionConfig() error = %v", err)
	}
	if cfg.APIURL != "https://control.example.test/root" {
		t.Fatalf("APIURL = %q, want normalized environment URL", cfg.APIURL)
	}
	if cfg.APIKey != "environment-key" {
		t.Fatalf("APIKey = %q, want environment override", cfg.APIKey)
	}
}

func TestLoadSessionConfigReadsFileAndRejectsUnsafeBaseURLParts(t *testing.T) {
	t.Parallel()

	sessionPath := filepath.Join(t.TempDir(), "session.json")
	data, err := json.Marshal(SessionConfig{
		APIURL: "http://127.0.0.1:8470",
		APIKey: "file-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sessionPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadSessionConfig(sessionPath, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("loadSessionConfig() error = %v", err)
	}
	if cfg.APIURL != defaultAPIURL || cfg.APIKey != "file-key" {
		t.Fatalf("loadSessionConfig() = %#v, want file values", cfg)
	}

	if _, err := normalizeAPIURL("http://user:pass@127.0.0.1:8470?token=secret"); err == nil {
		t.Fatal("normalizeAPIURL() accepted credentials and a query string")
	}
	if _, err := normalizeAPIURL("file:///tmp/luminet.sock"); err == nil {
		t.Fatal("normalizeAPIURL() accepted a non-HTTP scheme")
	}
}
