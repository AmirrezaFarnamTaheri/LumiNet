package proxy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVoidTunnelManager_New(t *testing.T) {
	mgr := NewVoidTunnelManager(12345)
	if mgr == nil {
		t.Fatal("expected manager instance, got nil")
	}

	if mgr.socksPort != 12345 {
		t.Errorf("expected socksPort 12345, got %d", mgr.socksPort)
	}

	if mgr.tunDevice != "tun0" {
		t.Errorf("expected tunDevice tun0, got %s", mgr.tunDevice)
	}
}

func TestVoidTunnelManager_EnableTUNPlatformCheck(t *testing.T) {
	mgr := NewVoidTunnelManager(12345)
	defer mgr.Close()

	if runtime.GOOS != "linux" {
		err := mgr.EnableTUN("1.1.1.1")
		if err == nil {
			t.Error("expected error on non-Linux platform, got nil")
		}
	}
}

func TestVoidTunnelManager_WriteCleanupState(t *testing.T) {
	mgr := NewVoidTunnelManager(12345)
	defer mgr.Close()

	// Override paths for testing to avoid touching system locations
	tempDir, err := os.MkdirTemp("", "voidtunnel_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	mgr.statePath = filepath.Join(tempDir, "state.json")
	mgr.cleanupScriptPath = filepath.Join(tempDir, "cleanup.sh")

	mgr.state = VoidTunnelState{
		OriginalGateway:   "192.168.1.1",
		OriginalInterface: "eth0",
		RemoteServerIP:    "8.8.8.8",
		Active:            true,
	}

	mgr.writeState()
	mgr.generateCleanupScript()

	// Check if state file was created
	if _, err := os.Stat(mgr.statePath); err != nil {
		t.Errorf("expected state file to exist: %v", err)
	}

	// Check if cleanup script was created
	if _, err := os.Stat(mgr.cleanupScriptPath); err != nil {
		t.Errorf("expected cleanup script to exist: %v", err)
	}

	// Verify cleanup script content
	content, err := os.ReadFile(mgr.cleanupScriptPath)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(content), "192.168.1.1") {
		t.Errorf("cleanup script does not contain expected gateway: %s", string(content))
	}
}
