package system

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// AtomicCacheStore persists key-value pairs atomically to a JSON file.
type AtomicCacheStore struct {
	mu   sync.Mutex
	path string
	data map[string]string
}

// NewAtomicCacheStore creates a new AtomicCacheStore backed by the given file path.
func NewAtomicCacheStore(path string) *AtomicCacheStore {
	store := &AtomicCacheStore{path: path, data: make(map[string]string)}
	// Load existing data if the file exists
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &store.data)
	}
	return store
}

// Set stores a key-value pair and persists it to disk.
func (s *AtomicCacheStore) Set(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = value
	raw, err := json.Marshal(s.data)
	if err != nil {
		return fmt.Errorf("AtomicCacheStore: marshal failed: %w", err)
	}
	return os.WriteFile(s.path, raw, 0600)
}

// Get retrieves a value for the given key.
func (s *AtomicCacheStore) Get(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	val, ok := s.data[key]
	return val, ok
}
