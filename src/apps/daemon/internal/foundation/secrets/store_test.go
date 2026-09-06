package secrets

import (
	"context"
	"os"
	"testing"
)

func TestFileStoreLifecycle(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "luminet-secrets-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	masterKey := []byte("test-master-key-entropy")
	store, err := NewFileStore(tempDir, masterKey)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	ctx := context.Background()
	ref := "test/ddns_token"
	val := []byte("secret_api_token_value_xyz")

	// Verify secret is not found initially
	_, err = store.Get(ctx, ref)
	if err == nil {
		t.Errorf("expected Get to fail for absent key")
	}
	if _, ok := err.(ErrNotFound); !ok {
		t.Errorf("expected ErrNotFound, got: %T %v", err, err)
	}

	// Put secret
	if err := store.Put(ctx, ref, val); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Get secret and verify value
	got, err := store.Get(ctx, ref)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if string(got) != string(val) {
		t.Errorf("Get returned %q, want %q", string(got), string(val))
	}

	// Verify encryption at rest (reading file directly shouldn't be plain text)
	filePath := store.refPath(ref)
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read raw encrypted file: %v", err)
	}
	if string(fileBytes) == string(val) {
		t.Errorf("raw file contains plaintext data!")
	}

	// List secrets
	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(list) != 1 || list[0] != "test_ddns_token" {
		t.Errorf("List returned unexpected keys: %v", list)
	}

	// Delete secret
	if err := store.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify secret is gone
	_, err = store.Get(ctx, ref)
	if err == nil {
		t.Errorf("expected Get to fail after deletion")
	}
}
