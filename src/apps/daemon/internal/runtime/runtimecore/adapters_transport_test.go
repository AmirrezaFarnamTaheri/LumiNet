package runtimecore

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeExecutableForTest(t *testing.T, path string) {
	t.Helper()
	content := []byte("#!/bin/sh\nexit 0\n")
	mode := os.FileMode(0o755)
	if runtime.GOOS == "windows" {
		content = []byte("@exit /b 0\r\n")
		mode = 0o644
	}
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
}

func TestResolveTorTransportExecutableFromPATH(t *testing.T) {
	dir := t.TempDir()
	name := "snowflake-client"
	if runtime.GOOS == "windows" {
		name += ".bat"
	}
	path := filepath.Join(dir, name)
	writeExecutableForTest(t, path)
	t.Setenv("PATH", dir)

	got, err := resolveTorTransportExecutable(name)
	if err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs(path)
	if filepath.Clean(got) != filepath.Clean(abs) {
		t.Fatalf("resolved=%q want=%q", got, abs)
	}
}

func TestResolveTorTransportExecutableFromRepositoryBundle(t *testing.T) {
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "bin", "tor"), 0o755); err != nil {
		t.Fatal(err)
	}
	name := "webtunnel-client"
	path := filepath.Join(dir, "bin", "tor", name)
	writeExecutableForTest(t, path)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	t.Setenv("PATH", "")

	got, err := resolveTorTransportExecutable(name)
	if err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs(path)
	if filepath.Clean(got) != filepath.Clean(abs) {
		t.Fatalf("resolved=%q want=%q", got, abs)
	}
}

func TestResolveTorTransportExecutableMissingFailsClosed(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, err := resolveTorTransportExecutable("definitely-missing-transport")
	if err == nil || !strings.Contains(err.Error(), "was not found") {
		t.Fatalf("error=%v, want explicit not-found failure", err)
	}
}

func TestResolveTorTransportExecutableRejectsNonExecutableBundleFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows executable permission is extension-based")
	}
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "bin", "tor"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bin", "tor", "lyrebird")
	if err := os.WriteFile(path, []byte("not executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	t.Setenv("PATH", "")
	if _, err := resolveTorTransportExecutable("lyrebird"); err == nil {
		t.Fatal("non-executable repository transport was accepted")
	}
}

func TestProductionPreflightResolvesTransportBeforeFactory(t *testing.T) {
	dir := t.TempDir()
	name := "snowflake-client"
	path := filepath.Join(dir, name)
	writeExecutableForTest(t, path)
	t.Setenv("PATH", dir)

	got, err := productionPreflight(Request{
		Engine:           EngineTor,
		TransportPlugins: []TorTransportPlugin{{Name: "snowflake", Executable: name}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.TransportPlugins) != 1 || !filepath.IsAbs(got.TransportPlugins[0].Executable) {
		t.Fatalf("preflight plugin=%+v", got.TransportPlugins)
	}
}

func TestProductionPreflightMissingTransportFailsClosed(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, err := productionPreflight(Request{
		Engine:           EngineTor,
		TransportPlugins: []TorTransportPlugin{{Name: "snowflake", Executable: "snowflake-client"}},
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("error=%v, want ErrInvalidRequest", err)
	}
}
