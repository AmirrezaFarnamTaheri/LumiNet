package system

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func waitForWatcherCount(t *testing.T, count *int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(count) >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("watcher callback count=%d, want >= %d", atomic.LoadInt32(count), want)
}

func TestConfigWatcher_Debounce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	var count int32
	cw, err := NewConfigWatcher([]string{path}, func(got string) {
		if got != path {
			t.Errorf("callback path=%q want %q", got, path)
		}
		atomic.AddInt32(&count, 1)
	}, 75*time.Millisecond)
	if err != nil {
		t.Fatalf("failed to create ConfigWatcher: %v", err)
	}
	defer cw.Close()

	for i := 0; i < 5; i++ {
		if err := os.WriteFile(path, []byte("update=true"), 0o600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	waitForWatcherCount(t, &count, 1)
	time.Sleep(150 * time.Millisecond)
	if got := atomic.LoadInt32(&count); got != 1 {
		t.Fatalf("expected exactly one debounced callback, got %d", got)
	}
}

func TestConfigWatcher_SurvivesAtomicReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}

	var count int32
	cw, err := NewConfigWatcher([]string{path}, func(string) { atomic.AddInt32(&count, 1) }, 40*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer cw.Close()

	for i := 0; i < 2; i++ {
		tmp := filepath.Join(dir, "config.tmp")
		if err := os.WriteFile(tmp, []byte{byte('2' + i)}, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, path); err != nil {
			t.Fatal(err)
		}
		waitForWatcherCount(t, &count, int32(i+1))
		time.Sleep(80 * time.Millisecond)
	}
}

func TestConfigWatcher_FiltersSiblingEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	sibling := filepath.Join(dir, "other.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sibling, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	var count int32
	cw, err := NewConfigWatcher([]string{path}, func(string) { atomic.AddInt32(&count, 1) }, 40*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer cw.Close()
	if err := os.WriteFile(sibling, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if got := atomic.LoadInt32(&count); got != 0 {
		t.Fatalf("sibling event triggered watched callback: %d", got)
	}
}
