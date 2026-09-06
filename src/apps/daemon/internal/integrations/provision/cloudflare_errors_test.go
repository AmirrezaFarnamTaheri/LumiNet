package provision

import (
	"strings"
	"testing"
)

func TestFormatCloudflareAPIErrorExtractsStructuredErrorsAndRetryHint(t *testing.T) {
	err := formatCloudflareAPIError(429, []byte(`{"errors":[{"code":1015,"message":"rate limited"},{"message":"try later"}]}`), "120")
	got := err.Error()
	for _, want := range []string{"HTTP error 429", "rate limited (code 1015)", "try later", "Retry-After: 120"} {
		if !strings.Contains(got, want) {
			t.Fatalf("error %q missing %q", got, want)
		}
	}
}

func TestFormatCloudflareAPIErrorFallsBackToBoundedBody(t *testing.T) {
	err := formatCloudflareAPIError(500, []byte("provider unavailable"), "")
	if got := err.Error(); got != "HTTP error 500: provider unavailable" {
		t.Fatalf("got %q", got)
	}
}
