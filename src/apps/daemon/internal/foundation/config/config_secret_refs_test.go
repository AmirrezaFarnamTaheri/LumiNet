package config

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type nativeMemoryStore struct {
	mu     sync.Mutex
	values map[string][]byte
}

func (s *nativeMemoryStore) ProviderName() string { return "test-native" }
func (*nativeMemoryStore) Native() bool           { return true }
func (s *nativeMemoryStore) Put(_ context.Context, ref string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.values == nil {
		s.values = map[string][]byte{}
	}
	s.values[ref] = append([]byte(nil), value...)
	return nil
}
func (s *nativeMemoryStore) Get(_ context.Context, ref string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.values[ref]...), nil
}
func (s *nativeMemoryStore) Delete(_ context.Context, ref string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, ref)
	return nil
}
func (s *nativeMemoryStore) List(context.Context) ([]string, error) { return nil, nil }

func TestSavePersistsDDNSSecretByReference(t *testing.T) {
	store := &nativeMemoryStore{}
	path := filepath.Join(t.TempDir(), "config.json")
	manager := NewManagerWithSecretStore(path, store)
	cfg := DefaultConfig()
	cfg.DDNS.Token = "do-not-persist-this-token"
	saveCurrentConfig(t, manager, cfg)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), cfg.DDNS.Token) {
		t.Fatalf("config file contains plaintext token: %s", raw)
	}
	var persisted struct {
		DDNS DDNSConfig `json:"ddns"`
	}
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.DDNS.Token != "" || persisted.DDNS.TokenRef.Provider != "test-native" || persisted.DDNS.TokenRef.Ref == "" {
		t.Fatalf("persisted DDNS secret = %#v", persisted.DDNS)
	}

	reloaded, err := NewManagerWithSecretStore(path, store).Load()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.DDNS.Token != "do-not-persist-this-token" {
		t.Fatalf("hydrated token = %q", reloaded.DDNS.Token)
	}
}
