package certs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCertMagicFileStorageContainsKeys(t *testing.T) {
	root := t.TempDir()
	storage := NewCertMagicFileStorage(root)
	outside := filepath.Join(filepath.Dir(root), "outside-certmagic")
	if err := os.WriteFile(outside, []byte("preserve"), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	defer os.Remove(outside)

	for _, key := range []string{"", "../outside-certmagic", "nested/../../outside-certmagic", "/absolute", `C:\\absolute`} {
		if err := storage.Store(context.Background(), key, []byte("replace")); err == nil {
			t.Errorf("Store(%q) succeeded, want rejection", key)
		}
		if err := storage.Delete(context.Background(), key); err == nil {
			t.Errorf("Delete(%q) succeeded, want rejection", key)
		}
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "preserve" {
		t.Fatalf("outside sentinel changed: data=%q err=%v", data, err)
	}
}

func TestCertMagicFileStorageReclaimsStaleLock(t *testing.T) {
	storage := NewCertMagicFileStorage(t.TempDir())
	previousStaleDuration := lockStaleDuration
	previousHeartbeatInterval := lockHeartbeatInterval
	lockStaleDuration = time.Millisecond
	lockHeartbeatInterval = time.Hour
	t.Cleanup(func() {
		lockStaleDuration = previousStaleDuration
		lockHeartbeatInterval = previousHeartbeatInterval
	})

	lockPath, err := storage.path("acme/example.lock")
	if err != nil {
		t.Fatalf("lock path: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		t.Fatalf("create lock directory: %v", err)
	}
	timestamp, _ := time.Now().Add(-time.Second).MarshalText()
	if err := os.WriteFile(lockPath, timestamp, 0o600); err != nil {
		t.Fatalf("write stale lock: %v", err)
	}

	if err := storage.Lock(context.Background(), "acme/example"); err != nil {
		t.Fatalf("Lock stale entry: %v", err)
	}
	if err := storage.Unlock(context.Background(), "acme/example"); err != nil {
		t.Fatalf("Unlock reclaimed entry: %v", err)
	}
}

func TestCertMagicFileStorageRejectsSymlinkedParent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Skipf("creating test symlink: %v", err)
	}
	storage := NewCertMagicFileStorage(root)
	if err := storage.Store(context.Background(), "linked/certificate.pem", []byte("certificate")); err == nil {
		t.Fatal("Store through symlink succeeded, want rejection")
	}
	if _, err := os.Stat(filepath.Join(outside, "certificate.pem")); !os.IsNotExist(err) {
		t.Fatalf("outside file was created: %v", err)
	}
}

func TestCertMagicFileStorageNestedLifecycle(t *testing.T) {
	storage := NewCertMagicFileStorage(t.TempDir())
	ctx := context.Background()
	key := "certs/example.pem"
	if err := storage.Store(ctx, key, []byte("certificate")); err != nil {
		t.Fatalf("Store: %v", err)
	}
	data, err := storage.Load(ctx, key)
	if err != nil || string(data) != "certificate" {
		t.Fatalf("Load: data=%q err=%v", data, err)
	}
	keys, err := storage.List(ctx, "", true)
	if err != nil || len(keys) != 1 || keys[0] != key {
		t.Fatalf("List: keys=%v err=%v", keys, err)
	}
	if err := storage.Lock(ctx, "acme/example"); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if err := storage.Unlock(ctx, "acme/example"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
}
