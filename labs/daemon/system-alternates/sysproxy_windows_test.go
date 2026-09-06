//go:build windows

package system

import (
	"encoding/json"
	"os"
	"testing"

	"golang.org/x/sys/windows/registry"
)

func TestSysproxyBackupAndRestore(t *testing.T) {
	// 1. Save current registry settings
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("failed to query registry: %v", err)
	}
	originalEnable, _, _ := k.GetIntegerValue("ProxyEnable")
	originalServer, _, _ := k.GetStringValue("ProxyServer")
	originalOverride, _, _ := k.GetStringValue("ProxyOverride")
	k.Close()

	// Clean up any stale backup file
	filePath := getBackupFilePath()
	if filePath != "" {
		_ = os.Remove(filePath)
	}

	// 2. Modify registry to a known state for test
	kWrite, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		t.Fatalf("failed to write registry: %v", err)
	}
	_ = kWrite.SetDWordValue("ProxyEnable", 1)
	_ = kWrite.SetStringValue("ProxyServer", "9.9.9.9:9999")
	_ = kWrite.SetStringValue("ProxyOverride", "my-bypass")
	kWrite.Close()

	// 3. Trigger backup
	backupSystemProxy()

	// Verify backup file was created
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Fatalf("expected backup file to exist")
	}

	// Verify backup content
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read backup file: %v", err)
	}
	var backup sysproxyBackup
	if err := json.Unmarshal(data, &backup); err != nil {
		t.Fatalf("failed to parse backup: %v", err)
	}
	if backup.ProxyEnable != 1 || backup.ProxyServer != "9.9.9.9:9999" || backup.ProxyOverride != "my-bypass" {
		t.Errorf("unexpected backup data: %+v", backup)
	}

	// 4. Modify registry again to simulate a session
	kWrite2, _ := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	_ = kWrite2.SetDWordValue("ProxyEnable", 0)
	_ = kWrite2.SetStringValue("ProxyServer", "127.0.0.1:8080")
	kWrite2.Close()

	// 5. Restore
	if err := restoreSystemProxy(); err != nil {
		t.Fatalf("restoreSystemProxy failed: %v", err)
	}

	// Verify backup file was deleted
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Errorf("expected backup file to be deleted after restore")
	}

	// Verify registry was restored to backup state (1, 9.9.9.9:9999, my-bypass)
	kRead, _ := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	enable, _, _ := kRead.GetIntegerValue("ProxyEnable")
	server, _, _ := kRead.GetStringValue("ProxyServer")
	override, _, _ := kRead.GetStringValue("ProxyOverride")
	kRead.Close()

	if enable != 1 || server != "9.9.9.9:9999" || override != "my-bypass" {
		t.Errorf("registry restore mismatch: enable=%d, server=%q, override=%q", enable, server, override)
	}

	// 6. Restore registry to original user state to leave clean system
	kRestore, _ := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	_ = kRestore.SetDWordValue("ProxyEnable", uint32(originalEnable))
	if originalServer != "" {
		_ = kRestore.SetStringValue("ProxyServer", originalServer)
	} else {
		_ = kRestore.DeleteValue("ProxyServer")
	}
	if originalOverride != "" {
		_ = kRestore.SetStringValue("ProxyOverride", originalOverride)
	} else {
		_ = kRestore.DeleteValue("ProxyOverride")
	}
	kRestore.Close()
}
