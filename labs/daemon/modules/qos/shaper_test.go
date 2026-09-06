package qos

import (
	"context"
	"testing"
	"time"
)

func TestShaper_WaitN(t *testing.T) {
	shaper := NewShaper(1024 * 1024) // 1MB/s
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err := shaper.WaitN(ctx, 1024)
	if err != nil {
		t.Fatalf("expected WaitN to succeed, got %v", err)
	}
}
