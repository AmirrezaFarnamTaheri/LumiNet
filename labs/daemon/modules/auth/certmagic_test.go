package auth

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileCertStorageRejectsEscapingKeys(t *testing.T) {
	storageRoot := t.TempDir()
	storage, err := NewFileCertStorage(storageRoot)
	if err != nil {
		t.Fatalf("NewFileCertStorage: %v", err)
	}

	for _, key := range []string{"", "../escape", "nested/../../escape", "/absolute", `C:\\escape`} {
		if err := storage.Store(context.Background(), key, []byte("value")); err == nil {
			t.Errorf("Store(%q) succeeded, want rejection", key)
		}
	}

	outside := filepath.Join(filepath.Dir(storageRoot), "outside-cert")
	if err := os.WriteFile(outside, []byte("preserve"), 0o600); err != nil {
		t.Fatalf("write outside sentinel: %v", err)
	}
	defer os.Remove(outside)
	if err := storage.Delete(context.Background(), "../outside-cert"); err == nil {
		t.Fatal("Delete traversal succeeded, want rejection")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("outside sentinel was affected: %v", err)
	}
}

func TestFileCertStorageAllowsNestedKeysAndRootListing(t *testing.T) {
	storage, err := NewFileCertStorage(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileCertStorage: %v", err)
	}
	if err := storage.Store(context.Background(), "certs/example.pem", []byte("certificate")); err != nil {
		t.Fatalf("Store nested key: %v", err)
	}
	keys, err := storage.List(context.Background(), "", true)
	if err != nil {
		t.Fatalf("List root: %v", err)
	}
	if len(keys) != 1 || keys[0] != "certs/example.pem" {
		t.Fatalf("List root = %v, want nested key", keys)
	}
}

func TestFileCertStorageDeletesPrefixThroughCanonicalStore(t *testing.T) {
	storage, err := NewFileCertStorage(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileCertStorage: %v", err)
	}
	ctx := context.Background()
	for _, key := range []string{"certs/a.pem", "certs/nested/b.pem"} {
		if err := storage.Store(ctx, key, []byte(key)); err != nil {
			t.Fatalf("Store(%q): %v", key, err)
		}
	}
	if err := storage.Delete(ctx, "certs"); err != nil {
		t.Fatalf("Delete prefix: %v", err)
	}
	if storage.Exists(ctx, "certs/a.pem") || storage.Exists(ctx, "certs/nested/b.pem") {
		t.Fatal("Delete prefix left certificate data behind")
	}
}
