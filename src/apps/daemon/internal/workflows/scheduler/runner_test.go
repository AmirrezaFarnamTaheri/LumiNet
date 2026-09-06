package scheduler

import (
	"context"
	"testing"
	"time"
)

func TestRunnerRejectsConcurrentStart(t *testing.T) {
	runner := NewRunner()
	if err := runner.Register(&Job{
		ID:       "heartbeat",
		Interval: time.Hour,
		RunFunc: func(context.Context) error {
			return nil
		},
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := runner.Start(ctx); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	if err := runner.Start(ctx); err == nil {
		cancel()
		_ = runner.Stop()
		t.Fatal("second Start succeeded; want an already-running error")
	}
	if err := runner.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestRunnerCanRestartAfterStop(t *testing.T) {
	runner := NewRunner()
	if err := runner.Register(&Job{
		ID:       "heartbeat",
		Interval: time.Hour,
		RunFunc: func(context.Context) error {
			return nil
		},
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	if err := runner.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if err := runner.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}
