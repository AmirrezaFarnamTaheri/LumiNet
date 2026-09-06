package auth

import (
	"context"
	"testing"
)

func TestAcmeResolver_Local(t *testing.T) {
	resolver := NewAcmeResolver()
	ok, err := resolver.CheckPreflight(context.Background(), "invalid-non-existent-domain-acme-test.org", "dummytxt")
	if err != nil {
		t.Logf("Expected lookup failure: %v", err)
		return
	}
	if ok {
		t.Errorf("expected preflight to fail for non-existent domain")
	}
}
