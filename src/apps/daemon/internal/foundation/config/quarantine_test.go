package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadQuarantinesStructurallyCorruptConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	original := []byte(`{"server_addr":`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	manager := NewManagerWithSecretStore(path, nil)
	_, err := manager.Load()
	if err == nil {
		t.Fatal("Load() error=nil, want structural parse failure")
	}
	if !strings.Contains(err.Error(), "quarantined") {
		t.Fatalf("Load() error=%q, want quarantine location", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("corrupt active config still exists: %v", statErr)
	}
	entries, err := filepath.Glob(path + ".corrupt*")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("quarantine files=%v, want exactly one", entries)
	}
	got, err := os.ReadFile(entries[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("quarantined bytes changed: got %q want %q", got, original)
	}
}

func TestQuarantineDoesNotOverwriteEarlierEvidence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path+".corrupt", []byte("older"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	manager := NewManagerWithSecretStore(path, nil)
	_, _ = manager.Load()
	older, err := os.ReadFile(path + ".corrupt")
	if err != nil {
		t.Fatal(err)
	}
	if string(older) != "older" {
		t.Fatalf("older evidence overwritten: %q", older)
	}
	if _, err := os.Stat(path + ".corrupt.1"); err != nil {
		t.Fatalf("second quarantine missing: %v", err)
	}
}

func TestQuarantineCorruptConfigFailsClosedWhenNameBudgetExhausted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxCorruptConfigQuarantines; i++ {
		candidate := path + ".corrupt"
		if i > 0 {
			candidate = fmt.Sprintf("%s.corrupt.%d", path, i)
		}
		if err := os.WriteFile(candidate, []byte("prior"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := quarantineCorruptConfig(path); err == nil {
		t.Fatal("expected quarantine name exhaustion")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "damaged" {
		t.Fatalf("active damaged evidence changed: %q err=%v", got, err)
	}
}
