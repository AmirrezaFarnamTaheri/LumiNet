package diagnostics

import (
	"context"
	"strings"
	"testing"
)

func TestEvalQueryBasicAndBounded(t *testing.T) {
	got, err := EvalQuery(context.Background(), ".items[]", map[string]any{"items": []any{1, 2, 3}})
	if err != nil || len(got) != 3 {
		t.Fatalf("basic EvalQuery = %#v, %v", got, err)
	}
	_, err = EvalQuery(context.Background(), "range(0;5000)", nil)
	if err == nil || !strings.Contains(err.Error(), "result limit") {
		t.Fatalf("expected bounded-output error, got %v", err)
	}
}

func TestEvalQueryHonorsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := EvalQuery(ctx, "range(0;1000000)", nil)
	if err == nil {
		t.Fatal("expected canceled context error")
	}
}
