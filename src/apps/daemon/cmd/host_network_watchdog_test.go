package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestHostNetworkWatchdogUnexpectedExitCancelsDaemon(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	w := &hostNetworkWatchdog{done: make(chan struct{})}
	w.waitErr = errors.New("boom")
	close(w.done)

	monitorHostNetworkWatchdog(ctx, w, cancel)
	cause := context.Cause(ctx)
	if cause == nil || !strings.Contains(cause.Error(), "host-network watchdog exited unexpectedly") {
		t.Fatalf("cancellation cause = %v", cause)
	}
}

func TestHostNetworkWatchdogOwnedStopDoesNotCancelDaemon(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	w := &hostNetworkWatchdog{done: make(chan struct{})}
	w.stopping.Store(true)
	close(w.done)

	monitorHostNetworkWatchdog(ctx, w, cancel)
	if cause := context.Cause(ctx); cause != nil {
		t.Fatalf("owned watchdog stop cancelled daemon: %v", cause)
	}
}
