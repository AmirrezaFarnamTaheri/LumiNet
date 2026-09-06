package captcha

import (
	"context"
	"strings"
	"testing"
)

func TestSolveTurnstile(t *testing.T) {
	s := NewWebviewSolver()
	ctx := context.Background()

	token, err := s.SolveTurnstile(ctx, "0x4AAAAAAABcde123", "https://example.com/sub")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(token, "turnstile_token_") {
		t.Errorf("invalid token format: %s", token)
	}
}

func TestSolveHCaptcha(t *testing.T) {
	s := NewWebviewSolver()
	ctx := context.Background()

	token, err := s.SolveHCaptcha(ctx, "10000000-ffff-ffff-ffff-100000000001", "https://example.com/sub")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(token, "hcaptcha_token_") {
		t.Errorf("invalid token format: %s", token)
	}
}
