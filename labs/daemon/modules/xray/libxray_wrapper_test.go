package xray

import (
	"context"
	"errors"
	"testing"
)

func TestEmbeddedWrapperNeverReportsStubSessionRunning(t *testing.T) {
	wrapper := NewXrayWrapper()
	if err := wrapper.RunXray(`{"inbounds":[]}`); !errors.Is(err, ErrNativeCoreUnavailable) {
		t.Fatalf("RunXray() error = %v", err)
	}
	if wrapper.IsRunning() {
		t.Fatal("unavailable wrapper reported a running native session")
	}
	if got := QueryVersion(); got != "unavailable" {
		t.Fatalf("QueryVersion() = %q", got)
	}
}

func TestEmbeddedWrapperValidatesConfigurationBeforeUnavailable(t *testing.T) {
	wrapper := NewXrayWrapper()
	if err := wrapper.RunXray("not-json"); err == nil || errors.Is(err, ErrNativeCoreUnavailable) {
		t.Fatalf("malformed config error = %v", err)
	}
}

func TestProcessManagerStatsAreExplicitlyUnavailable(t *testing.T) {
	manager := NewXrayProcessManager("config.json", "127.0.0.1:10085")
	_, _, err := manager.QueryTrafficStats(context.Background())
	if !errors.Is(err, ErrTrafficStatsUnavailable) {
		t.Fatalf("QueryTrafficStats() error = %v", err)
	}
}
