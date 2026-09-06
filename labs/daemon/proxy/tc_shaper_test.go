package proxy

import (
	"context"
	"runtime"
	"testing"
)

func TestTcShaperCompileAndStub(t *testing.T) {
	shaper := NewTcShaper()
	if shaper == nil {
		t.Fatal("NewTcShaper returned nil")
	}

	ctx := context.Background()
	err := shaper.LimitPort(ctx, "eth0", 8080, 1024)

	if runtime.GOOS == "linux" {
		// On Linux, we might not have root permissions or 'tc' binary in tests,
		// but we can check if it tries to run something and returns an error or success.
		t.Logf("Linux tc shaper result: %v", err)
	} else {
		// On non-Linux, it must return the stub error.
		if err == nil {
			t.Error("expected error on non-Linux, got nil")
		} else if err.Error() != "tc shaping is only supported on Linux" {
			t.Errorf("unexpected error: %v", err)
		}
	}
}
