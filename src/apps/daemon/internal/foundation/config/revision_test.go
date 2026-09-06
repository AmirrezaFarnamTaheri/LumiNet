package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func saveCurrentConfig(t *testing.T, manager *Manager, cfg *Config) uint64 {
	t.Helper()
	_, revision := manager.GetWithRevision()
	newRevision, err := manager.SaveIfRevision(cfg, revision)
	if err != nil {
		t.Fatalf("SaveIfRevision() error = %v", err)
	}
	return newRevision
}

func TestSavePublishesOwnedSnapshotWithGeneratedSecretRefs(t *testing.T) {
	store := &nativeMemoryStore{}
	manager := NewManagerWithSecretStore(filepath.Join(t.TempDir(), "config.json"), store)
	cfg := DefaultConfig()
	cfg.DDNS.Token = "provider-secret"
	cfg.DecoyTraffic.Targets = []string{"https://one.example"}
	cfg.UpdateAdmission.TrustedKeys = map[string]string{"release": "public-key"}
	cfg.ProxyNodes = []ProxyNodeConfig{{ID: "node-1", Password: "node-secret"}}

	saveCurrentConfig(t, manager, cfg)
	published, revision := manager.GetWithRevision()
	if revision != 1 {
		t.Fatalf("revision=%d, want 1", revision)
	}
	if published.DDNS.Token != "provider-secret" || published.DDNS.TokenRef.Ref == "" {
		t.Fatalf("published DDNS secret/ref = %#v", published.DDNS)
	}
	if len(published.ProxyNodes) != 1 || published.ProxyNodes[0].Password != "node-secret" || published.ProxyNodes[0].PasswordRef.Ref == "" {
		t.Fatalf("published proxy node = %#v", published.ProxyNodes)
	}

	// Mutating the caller-owned object after persistence must not mutate authority.
	cfg.LogLevel = "caller-mutated"
	cfg.DecoyTraffic.Targets[0] = "https://mutated.example"
	cfg.UpdateAdmission.TrustedKeys["release"] = "mutated"
	cfg.ProxyNodes[0].Password = "mutated"
	got := manager.Get()
	if got.LogLevel == "caller-mutated" || got.DecoyTraffic.Targets[0] != "https://one.example" || got.UpdateAdmission.TrustedKeys["release"] != "public-key" || got.ProxyNodes[0].Password != "node-secret" {
		t.Fatalf("manager retained caller aliases: %#v", got)
	}

	// Mutating a returned snapshot must likewise remain caller-local.
	got.DecoyTraffic.Targets[0] = "https://returned-copy.example"
	got.UpdateAdmission.TrustedKeys["release"] = "returned-copy"
	got.ProxyNodes[0].Password = "returned-copy"
	again := manager.Get()
	if again.DecoyTraffic.Targets[0] != "https://one.example" || again.UpdateAdmission.TrustedKeys["release"] != "public-key" || again.ProxyNodes[0].Password != "node-secret" {
		t.Fatalf("Get returned aliased configuration: %#v", again)
	}
}

func TestSaveIfRevisionRejectsStaleWriterWithoutLosingNewerState(t *testing.T) {
	manager := NewManagerWithSecretStore(filepath.Join(t.TempDir(), "config.json"), &nativeMemoryStore{})
	saveCurrentConfig(t, manager, DefaultConfig())
	first, revision := manager.GetWithRevision()
	stale, staleRevision := manager.GetWithRevision()
	if revision != staleRevision {
		t.Fatalf("initial revisions differ: %d != %d", revision, staleRevision)
	}

	first.LogLevel = "debug"
	newRevision, err := manager.SaveIfRevision(first, revision)
	if err != nil {
		t.Fatal(err)
	}
	if newRevision != revision+1 {
		t.Fatalf("new revision=%d, want %d", newRevision, revision+1)
	}

	stale.LogLevel = "warn"
	currentRevision, err := manager.SaveIfRevision(stale, staleRevision)
	if !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("error=%v, want ErrRevisionConflict", err)
	}
	if currentRevision != newRevision {
		t.Fatalf("reported current revision=%d, want %d", currentRevision, newRevision)
	}
	if got := manager.Get().LogLevel; got != "debug" {
		t.Fatalf("log level=%q, stale writer overwrote newer state", got)
	}
}

func TestFailedSaveDoesNotAdvanceRevision(t *testing.T) {
	manager := NewManagerWithSecretStore(filepath.Join(t.TempDir(), "config.json"), &nativeMemoryStore{})
	before := manager.Revision()
	if _, err := manager.SaveIfRevision(nil, before); err == nil {
		t.Fatal("SaveIfRevision(nil) error=nil, want rejection")
	}
	if after := manager.Revision(); after != before {
		t.Fatalf("revision advanced from %d to %d after failed save", before, after)
	}
}

func TestUnchangedSecretKeepsCommittedReference(t *testing.T) {
	store := &nativeMemoryStore{}
	manager := NewManagerWithSecretStore(filepath.Join(t.TempDir(), "config.json"), store)
	cfg := DefaultConfig()
	cfg.DDNS.Token = "stable-secret"
	saveCurrentConfig(t, manager, cfg)
	first := manager.Get()
	firstRef := first.DDNS.TokenRef.Ref
	if firstRef == "" {
		t.Fatal("first secret ref is empty")
	}

	first.LogLevel = "debug"
	saveCurrentConfig(t, manager, first)
	second := manager.Get()
	if second.DDNS.TokenRef.Ref != firstRef {
		t.Fatalf("unchanged secret ref rotated from %q to %q", firstRef, second.DDNS.TokenRef.Ref)
	}
	secret, err := store.Get(context.Background(), firstRef)
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "stable-secret" {
		t.Fatalf("stored secret=%q, want stable-secret", secret)
	}
}

func TestChangedSecretUsesCopyOnWriteReference(t *testing.T) {
	store := &nativeMemoryStore{}
	manager := NewManagerWithSecretStore(filepath.Join(t.TempDir(), "config.json"), store)
	cfg := DefaultConfig()
	cfg.DDNS.Token = "old-secret"
	saveCurrentConfig(t, manager, cfg)
	before := manager.Get()
	oldRef := before.DDNS.TokenRef.Ref

	before.DDNS.Token = "new-secret"
	saveCurrentConfig(t, manager, before)
	after := manager.Get()
	if after.DDNS.TokenRef.Ref == "" || after.DDNS.TokenRef.Ref == oldRef {
		t.Fatalf("changed secret reused old ref %q", oldRef)
	}
	if _, present := store.values[oldRef]; present {
		t.Fatalf("superseded secret ref %q was not retired", oldRef)
	}
	secret, err := store.Get(context.Background(), after.DDNS.TokenRef.Ref)
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "new-secret" {
		t.Fatalf("new stored secret=%q, want new-secret", secret)
	}
}

func TestFailedConfigCommitRollsBackStagedSecretWithoutMutatingOldRef(t *testing.T) {
	store := &nativeMemoryStore{}
	tmp := t.TempDir()
	manager := NewManagerWithSecretStore(filepath.Join(tmp, "config.json"), store)
	cfg := DefaultConfig()
	cfg.DDNS.Token = "old-secret"
	saveCurrentConfig(t, manager, cfg)
	before, revision := manager.GetWithRevision()
	oldRef := before.DDNS.TokenRef.Ref

	blocker := filepath.Join(tmp, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager.configPath = filepath.Join(blocker, "config.json")
	before.DDNS.Token = "new-secret"
	if _, err := manager.SaveIfRevision(before, revision); err == nil {
		t.Fatal("SaveIfRevision error=nil, want filesystem failure")
	}
	if got := manager.Revision(); got != revision {
		t.Fatalf("revision advanced after failed commit: got %d want %d", got, revision)
	}
	current := manager.Get()
	if current.DDNS.Token != "old-secret" || current.DDNS.TokenRef.Ref != oldRef {
		t.Fatalf("authoritative config changed after failed commit: %#v", current.DDNS)
	}
	secret, err := store.Get(context.Background(), oldRef)
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "old-secret" {
		t.Fatalf("old ref was overwritten: got %q", secret)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.values) != 1 {
		t.Fatalf("staged secret leaked after rollback: refs=%v", store.values)
	}
}

func TestRevisionPersistsAcrossRestart(t *testing.T) {
	store := &nativeMemoryStore{}
	path := filepath.Join(t.TempDir(), "config.json")
	first := NewManagerWithSecretStore(path, store)
	saveCurrentConfig(t, first, DefaultConfig())
	if got := first.Revision(); got != 1 {
		t.Fatalf("first revision=%d, want 1", got)
	}

	second := NewManagerWithSecretStore(path, store)
	loaded, err := second.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := second.Revision(); got != 1 || loaded.ConfigRevision != 1 {
		t.Fatalf("restart revision manager=%d config=%d, want 1", got, loaded.ConfigRevision)
	}
	loaded.LogLevel = "debug"
	newRevision, err := second.SaveIfRevision(loaded, 1)
	if err != nil {
		t.Fatal(err)
	}
	if newRevision != 2 {
		t.Fatalf("post-restart revision=%d, want 2", newRevision)
	}
}

func TestLegacyConfigWithoutRevisionIsMigratedAtomically(t *testing.T) {
	store := &nativeMemoryStore{}
	path := filepath.Join(t.TempDir(), "config.json")
	legacy := DefaultConfig()
	legacy.ConfigRevision = 0
	raw, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	manager := NewManagerWithSecretStore(path, store)
	loaded, err := manager.Load()
	if err != nil {
		t.Fatal(err)
	}
	if manager.Revision() != 1 || loaded.ConfigRevision != 1 {
		t.Fatalf("legacy migration revision manager=%d config=%d, want 1", manager.Revision(), loaded.ConfigRevision)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Config
	if err := json.Unmarshal(persisted, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ConfigRevision != 1 {
		t.Fatalf("persisted legacy revision=%d, want 1", decoded.ConfigRevision)
	}
}

func TestReloadOfCurrentCommittedBytesDoesNotAdvanceRevision(t *testing.T) {
	store := &nativeMemoryStore{}
	path := filepath.Join(t.TempDir(), "config.json")
	manager := NewManagerWithSecretStore(path, store)
	cfg := DefaultConfig()
	saveCurrentConfig(t, manager, cfg)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if manager.Revision() != 1 {
		t.Fatalf("initial revision=%d, want 1", manager.Revision())
	}

	loaded, err := manager.Load()
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if manager.Revision() != 1 || loaded.ConfigRevision != 1 {
		t.Fatalf("self-reload revision manager=%d config=%d, want 1", manager.Revision(), loaded.ConfigRevision)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("self-reload rewrote byte-identical authoritative config")
	}
}

func TestExternalReloadWithReusedRevisionAdvancesGeneration(t *testing.T) {
	store := &nativeMemoryStore{}
	path := filepath.Join(t.TempDir(), "config.json")
	manager := NewManagerWithSecretStore(path, store)
	cfg := DefaultConfig()
	saveCurrentConfig(t, manager, cfg)
	if manager.Revision() != 1 {
		t.Fatalf("initial revision=%d, want 1", manager.Revision())
	}

	// Simulate a manual/external file edit that changes content but incorrectly
	// preserves the old generation. Load must assign a fresh generation so a
	// pre-edit ETag can never become valid for the new content.
	external := manager.Get()
	external.LogLevel = "warn"
	external.ConfigRevision = 1
	raw, err := json.MarshalIndent(external, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := manager.Load()
	if err != nil {
		t.Fatal(err)
	}
	if manager.Revision() != 2 || loaded.ConfigRevision != 2 {
		t.Fatalf("external reload revision manager=%d config=%d, want 2", manager.Revision(), loaded.ConfigRevision)
	}
	if loaded.LogLevel != "warn" {
		t.Fatalf("external content was not adopted: log_level=%q", loaded.LogLevel)
	}
}

func TestMutateRetriesFreshSnapshotAndPreservesConcurrentChange(t *testing.T) {
	manager := NewManagerWithSecretStore(filepath.Join(t.TempDir(), "config.json"), &nativeMemoryStore{})
	saveCurrentConfig(t, manager, DefaultConfig())

	calls := 0
	result, err := manager.Mutate(MutationOptions{MaxAttempts: 3}, func(candidate *Config) error {
		calls++
		candidate.LogLevel = "debug"
		if calls != 1 {
			return nil
		}

		concurrent, revision := manager.GetWithRevision()
		concurrent.DNSResolution = false
		concurrent.MaxConcurrency = 77
		if _, saveErr := manager.SaveIfRevision(concurrent, revision); saveErr != nil {
			return saveErr
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Mutate() error = %v", err)
	}
	if result.Attempts != 2 {
		t.Fatalf("attempts=%d, want 2", result.Attempts)
	}
	if calls != 2 {
		t.Fatalf("mutation calls=%d, want 2", calls)
	}
	got := manager.Get()
	if got.LogLevel != "debug" {
		t.Fatalf("LogLevel=%q, want debug", got.LogLevel)
	}
	if got.DNSResolution || got.MaxConcurrency != 77 {
		t.Fatalf("concurrent fields were lost: DNSResolution=%v MaxConcurrency=%d", got.DNSResolution, got.MaxConcurrency)
	}
	stats := manager.MutationStats()
	if stats.Calls != 1 || stats.Commits != 1 || stats.Conflicts != 1 || stats.AutomaticRetries != 1 || stats.ExhaustedRetries != 0 {
		t.Fatalf("MutationStats() = %+v, want calls=1 commits=1 conflicts=1 retries=1 exhausted=0", stats)
	}
}

func TestMutateExplicitRevisionNeverRetries(t *testing.T) {
	manager := NewManagerWithSecretStore(filepath.Join(t.TempDir(), "config.json"), &nativeMemoryStore{})
	saveCurrentConfig(t, manager, DefaultConfig())
	_, expected := manager.GetWithRevision()

	calls := 0
	result, err := manager.Mutate(MutationOptions{ExpectedRevision: &expected, MaxAttempts: MaxMutationAttempts}, func(candidate *Config) error {
		calls++
		candidate.LogLevel = "debug"
		concurrent, revision := manager.GetWithRevision()
		concurrent.MaxConcurrency = 91
		_, saveErr := manager.SaveIfRevision(concurrent, revision)
		return saveErr
	})
	if !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("Mutate() error=%v, want ErrRevisionConflict", err)
	}
	if result.Attempts != 1 || calls != 1 {
		t.Fatalf("attempts=%d calls=%d, want 1/1", result.Attempts, calls)
	}
	got := manager.Get()
	if got.LogLevel == "debug" || got.MaxConcurrency != 91 {
		t.Fatalf("explicit stale mutation overwrote authority: %#v", got)
	}
	stats := manager.MutationStats()
	if stats.Calls != 1 || stats.Commits != 0 || stats.Conflicts != 1 || stats.AutomaticRetries != 0 || stats.ExhaustedRetries != 0 {
		t.Fatalf("MutationStats() = %+v, explicit revision must never auto-retry", stats)
	}
}

func TestMutateRetryBudgetIsBounded(t *testing.T) {
	manager := NewManagerWithSecretStore(filepath.Join(t.TempDir(), "config.json"), &nativeMemoryStore{})
	saveCurrentConfig(t, manager, DefaultConfig())

	calls := 0
	result, err := manager.Mutate(MutationOptions{MaxAttempts: 2}, func(candidate *Config) error {
		calls++
		candidate.LogLevel = "debug"
		concurrent, revision := manager.GetWithRevision()
		concurrent.MaxConcurrency = 100 + calls
		_, saveErr := manager.SaveIfRevision(concurrent, revision)
		return saveErr
	})
	if !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("Mutate() error=%v, want ErrRevisionConflict", err)
	}
	if result.Attempts != 2 || calls != 2 {
		t.Fatalf("attempts=%d calls=%d, want 2/2", result.Attempts, calls)
	}
	if got := manager.Get().LogLevel; got == "debug" {
		t.Fatalf("exhausted mutation committed stale intent")
	}
	stats := manager.MutationStats()
	if stats.Calls != 1 || stats.Commits != 0 || stats.Conflicts != 2 || stats.AutomaticRetries != 1 || stats.ExhaustedRetries != 1 {
		t.Fatalf("MutationStats() = %+v, want calls=1 commits=0 conflicts=2 retries=1 exhausted=1", stats)
	}
}

func TestMutateCallbackErrorDoesNotAdvanceRevision(t *testing.T) {
	manager := NewManagerWithSecretStore(filepath.Join(t.TempDir(), "config.json"), &nativeMemoryStore{})
	saveCurrentConfig(t, manager, DefaultConfig())
	before := manager.Revision()
	wantErr := errors.New("reject mutation")
	result, err := manager.Mutate(MutationOptions{}, func(candidate *Config) error {
		candidate.LogLevel = "debug"
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Mutate() error=%v, want callback error", err)
	}
	if result.Attempts != 1 || result.Revision != before {
		t.Fatalf("result=%+v, want attempts=1 revision=%d", result, before)
	}
	if got := manager.Revision(); got != before {
		t.Fatalf("revision advanced from %d to %d", before, got)
	}
}
