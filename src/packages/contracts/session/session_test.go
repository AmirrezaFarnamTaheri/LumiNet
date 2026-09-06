package session

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestParseAcceptsBothLegacySessionShapes(t *testing.T) {
	t.Parallel()
	portLegacy, err := Parse([]byte(`{"port":"9123","api_key":"legacy-port-key"}`))
	if err != nil {
		t.Fatalf("Parse(port legacy) error = %v", err)
	}
	if portLegacy.APIURL != "http://127.0.0.1:9123" || portLegacy.APIKey != "legacy-port-key" {
		t.Fatalf("port legacy = %#v", portLegacy)
	}
	urlLegacy, err := Parse([]byte(`{"api_url":"http://localhost:8123/","api_key":"legacy-url-key"}`))
	if err != nil {
		t.Fatalf("Parse(url legacy) error = %v", err)
	}
	if urlLegacy.APIURL != "http://localhost:8123" || urlLegacy.APIKey != "legacy-url-key" {
		t.Fatalf("url legacy = %#v", urlLegacy)
	}
}

func TestParseRejectsUnsafeDiscoveredEndpoints(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		`{"api_url":"https://control.example.test","api_key":"k"}`,
		`{"api_url":"file:///tmp/luminet.sock","api_key":"k"}`,
		`{"api_url":"http://user:pass@127.0.0.1:8470","api_key":"k"}`,
		`{"api_url":"http://127.0.0.1:8470?token=secret","api_key":"k"}`,
		`{"port":"70000","api_key":"k"}`,
	} {
		if _, err := Parse([]byte(input)); err == nil {
			t.Fatalf("Parse(%s) accepted unsafe discovery endpoint", input)
		}
	}
}

func TestReadFileRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privilege-dependent on Windows")
	}
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	link := filepath.Join(dir, "session.json")
	if err := os.WriteFile(target, []byte(`{"port":"8470","api_key":"k"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(link); err == nil || !strings.Contains(strings.ToLower(err.Error()), "symlink") {
		t.Fatalf("ReadFile(symlink) error = %v, want symlink rejection", err)
	}
}

func TestWriteAndRemoveAreInstanceSafe(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "nested", "session.json")
	d := Descriptor{Version: CurrentVersion, InstanceID: "instance-new", APIURL: "http://127.0.0.1:8470", APIKey: "secret"}
	if err := WriteFileAtomic(path, d); err != nil {
		t.Fatalf("WriteFileAtomic() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("session permissions = %#o, want no group/other access", info.Mode().Perm())
	}
	got, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if got != d {
		t.Fatalf("ReadFile() = %#v, want %#v", got, d)
	}
	if err := RemoveIfOwned(path, "instance-old"); err != nil {
		t.Fatalf("RemoveIfOwned(old) error = %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("old instance removed current session: %v", err)
	}
	if err := RemoveIfOwned(path, d.InstanceID); err != nil {
		t.Fatalf("RemoveIfOwned(current) error = %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("session still exists after owner removal: %v", err)
	}
}

func TestSessionMutationsSerializeThroughLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	old := Descriptor{Version: CurrentVersion, InstanceID: "instance-old", APIURL: "http://127.0.0.1:8470"}
	newer := Descriptor{Version: CurrentVersion, InstanceID: "instance-new", APIURL: "http://127.0.0.1:8471"}
	if err := WriteFileAtomic(path, old); err != nil {
		t.Fatalf("WriteFileAtomic(old) error = %v", err)
	}

	lockPath := path + ".lock"
	if err := os.Mkdir(lockPath, 0o700); err != nil {
		t.Fatalf("create session mutation lock: %v", err)
	}

	writeDone := make(chan error, 1)
	go func() { writeDone <- WriteFileAtomic(path, newer) }()
	select {
	case err := <-writeDone:
		t.Fatalf("WriteFileAtomic ignored held mutation lock, err=%v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := os.Remove(lockPath); err != nil {
		t.Fatalf("release session mutation lock: %v", err)
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("WriteFileAtomic after lock release error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("WriteFileAtomic stayed blocked after lock release")
	}

	if err := os.Mkdir(lockPath, 0o700); err != nil {
		t.Fatalf("recreate session mutation lock: %v", err)
	}
	removeDone := make(chan error, 1)
	go func() { removeDone <- RemoveIfOwned(path, newer.InstanceID) }()
	select {
	case err := <-removeDone:
		t.Fatalf("RemoveIfOwned ignored held mutation lock, err=%v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := os.Remove(lockPath); err != nil {
		t.Fatalf("release session mutation lock for cleanup: %v", err)
	}
	select {
	case err := <-removeDone:
		if err != nil {
			t.Fatalf("RemoveIfOwned after lock release error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RemoveIfOwned stayed blocked after lock release")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("session still exists after serialized owner removal: %v", err)
	}
}

func TestCanonicalDescriptorRequiresVersionAndInstance(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(Descriptor{Version: CurrentVersion, APIURL: "http://127.0.0.1:8470"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(raw); err == nil {
		t.Fatal("Parse() accepted canonical descriptor without instance_id")
	}
}
