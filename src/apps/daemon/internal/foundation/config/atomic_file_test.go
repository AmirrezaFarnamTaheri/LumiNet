package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteAtomicPrivateFileIsDurableAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	want := []byte("{\"ok\":true}\n")
	if err := writeAtomicPrivateFile(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("contents = %q, want %q", got, want)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary file remains after success: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if gotMode := info.Mode().Perm(); gotMode != 0o600 {
			t.Fatalf("mode = %04o, want 0600", gotMode)
		}
	}
}
