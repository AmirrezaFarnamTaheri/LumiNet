package securefs

import (
	"bytes"
	"os"
	"testing"
)

func TestSecureFS(t *testing.T) {
	err := Init()
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Cleanup()

	securePath := GetSecureDir()
	if securePath == "" {
		t.Fatal("GetSecureDir returned empty path")
	}

	filename := "test_secret.txt"
	content := []byte("highly-sensitive-tor-config-details")

	// Write
	path, err := WriteFile(filename, content, 0600)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Verify file info
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat failed on written file: %v", err)
	}
	if info.Size() != int64(len(content)) {
		t.Errorf("Expected file size %d, got %d", len(content), info.Size())
	}

	// Read
	data, err := ReadFile(filename)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if !bytes.Equal(data, content) {
		t.Errorf("Expected content %s, got %s", content, data)
	}

	// Cleanup
	Cleanup()

	// Verify it's gone
	_, err = os.Stat(path)
	if err == nil {
		t.Error("Expected file to be deleted/unmounted after Cleanup, but it still exists")
	}
}
