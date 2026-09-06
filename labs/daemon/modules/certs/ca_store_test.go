package certs

import (
	"testing"
)

func TestMemoryCAStore(t *testing.T) {
	store := NewMemoryCAStore()

	// Initial checks
	if store.Enabled() {
		t.Error("new store should be disabled by default")
	}
	if _, _, ok := store.Load(); ok {
		t.Error("new store should not have CA loaded")
	}

	// Enable store
	store.SetEnabled(true)
	if !store.Enabled() {
		t.Error("store should be enabled")
	}

	// Generate CA
	cfg := DefaultCAConfig()
	cfg.Enabled = true
	cert, key, err := GenerateCA(cfg)
	if err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	// Store CA
	store.Store(cert, key)

	// Load and verify
	gotCert, gotKey, ok := store.Load()
	if !ok {
		t.Fatal("failed to load CA")
	}
	if gotCert.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("serial mismatch")
	}
	if gotKey != key {
		t.Errorf("key mismatch")
	}

	// Clear and verify
	store.Clear()
	if _, _, ok := store.Load(); ok {
		t.Error("store should be empty after clear")
	}

	// Disable and verify it cleans up
	store.Store(cert, key)
	store.SetEnabled(false)
	if store.Enabled() {
		t.Error("store should be disabled")
	}
	if _, _, ok := store.Load(); ok {
		t.Error("store should be cleared after disable")
	}
}

func TestGenerateCADisabled(t *testing.T) {
	cfg := DefaultCAConfig()
	cfg.Enabled = false
	_, _, err := GenerateCA(cfg)
	if err != ErrMITMDisabled {
		t.Errorf("expected ErrMITMDisabled, got %v", err)
	}
}
