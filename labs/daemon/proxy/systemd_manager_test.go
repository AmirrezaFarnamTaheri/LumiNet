package proxy

import (
	"context"
	"runtime"
	"testing"
)

func TestSystemdManagerCompileAndStub(t *testing.T) {
	mgr := NewSystemdManager()
	if mgr == nil {
		t.Fatal("NewSystemdManager returned nil")
	}

	svc := &SystemdService{
		Name:        "test-service",
		Description: "A test service unit",
		ExecStart:   "/usr/bin/test-app",
	}

	// Verify unit file generation behaves same everywhere
	unitStr := svc.GenerateUnit()
	if unitStr == "" || !containsString(unitStr, "Description=A test service unit") || !containsString(unitStr, "ExecStart=/usr/bin/test-app") {
		t.Errorf("Generated service unit string is invalid: %s", unitStr)
	}

	ctx := context.Background()
	err := mgr.InstallService(ctx, svc)

	if runtime.GOOS == "linux" {
		t.Logf("Linux systemd manager install result: %v", err)
	} else {
		// Must return stub error on non-Linux
		if err == nil {
			t.Error("expected error on non-Linux systemd manager, got nil")
		} else if err.Error() != "systemd is only supported on Linux" {
			t.Errorf("unexpected error: %v", err)
		}
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || s != "" && stringsContainsPolyfill(s, substr))
}

func stringsContainsPolyfill(s, substr string) bool {
	// A simple helper to avoid importing package strings in simple cases, or we can just import strings.
	// But let's just use strings.Contains for clarity:
	return contains(s, substr)
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
