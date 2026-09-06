package api

import (
	"strings"
	"testing"
)

func TestSanitizeQueryUsesSharedEncodedRedaction(t *testing.T) {
	got := sanitizeQuery("token%3Dencoded%2Dsecret&state=ok")
	if strings.Contains(got, "encoded%2Dsecret") {
		t.Fatalf("encoded secret leaked: %q", got)
	}
	if !strings.Contains(got, "token%3D***") || !strings.Contains(got, "state=ok") {
		t.Fatalf("unexpected sanitized query: %q", got)
	}
}
