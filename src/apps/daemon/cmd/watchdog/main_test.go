package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMonitorParentRecoversDurableStateWhenParentDies(t *testing.T) {
	recovered := make(chan string, 1)
	err := monitorParent(context.Background(), 42, t.TempDir(), time.Millisecond,
		func(pid int) bool { return false },
		func(_ context.Context, dir string) error {
			recovered <- dir
			return nil
		},
	)
	if err != nil {
		t.Fatalf("monitorParent returned error: %v", err)
	}
	select {
	case dir := <-recovered:
		if dir == "" {
			t.Fatal("recovery received an empty data directory")
		}
	default:
		t.Fatal("durable recovery was not called")
	}
}

func TestMonitorParentPropagatesRecoveryFailure(t *testing.T) {
	want := errors.New("restore failed")
	err := monitorParent(context.Background(), 42, t.TempDir(), time.Millisecond,
		func(pid int) bool { return false },
		func(context.Context, string) error { return want },
	)
	if !errors.Is(err, want) {
		t.Fatalf("monitorParent error = %v, want %v", err, want)
	}
}

func TestParseWatchdogArgsRequiresParentAndDataDir(t *testing.T) {
	if _, err := parseWatchdogArgs(nil); err == nil {
		t.Fatal("parseWatchdogArgs accepted missing required arguments")
	}
	cfg, err := parseWatchdogArgs([]string{"--parent-pid", "123", "--data-dir", "state"})
	if err != nil {
		t.Fatalf("parseWatchdogArgs: %v", err)
	}
	if cfg.parentPID != 123 || cfg.dataDir != "state" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}
