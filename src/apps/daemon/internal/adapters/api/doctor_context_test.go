package api

import (
	"context"
	"testing"
)

func TestCheckerFuncReceivesContext(t *testing.T) {
	type contextKey string
	const markerKey contextKey = "marker"

	ctx := context.WithValue(context.Background(), markerKey, "expected")
	checker := NewChecker("context", func(got context.Context) CheckResult {
		if got.Value(markerKey) != "expected" {
			t.Fatal("checker did not receive caller context")
		}
		return CheckResult{OK: true}
	})

	if result := checker.Check(ctx); !result.OK {
		t.Fatal("expected checker result to remain healthy")
	}
}
