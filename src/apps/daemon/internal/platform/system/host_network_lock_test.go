//go:build !windows

package system

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestHostNetworkLockNeverStealsFromLiveOwner(t *testing.T) {
	dir := t.TempDir()
	first, err := acquireHostNetworkLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Release()
	if _, err := acquireHostNetworkLock(dir); err == nil {
		t.Fatal("second process acquired a live host-network lock")
	}
}

func TestHostNetworkLockRecoversDeadOwner(t *testing.T) {
	dir := t.TempDir()
	lockDir := filepath.Join(dir, ".host-network.lock")
	if err := os.Mkdir(lockDir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(hostLockOwner{PID: 99999999, Token: "dead-owner"})
	if err := os.WriteFile(filepath.Join(lockDir, "owner.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	lock, err := acquireHostNetworkLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
}
