package runtimecore

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestProbeEngineReportsSSTPAvailability(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PATH fixture uses a unix executable")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "sstpc")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	capability := ProbeEngine(EngineSSTP)
	if !capability.Available || capability.Mode != "system-tunnel" || capability.BinaryPath != binary {
		t.Fatalf("capability=%+v", capability)
	}
}

func TestProbeEngineRejectsUnknownEngine(t *testing.T) {
	capability := ProbeEngine(Engine("unknown"))
	if capability.Available || capability.Mode != "unknown" || !strings.Contains(capability.Reason, "unsupported") {
		t.Fatalf("capability=%+v", capability)
	}
}
