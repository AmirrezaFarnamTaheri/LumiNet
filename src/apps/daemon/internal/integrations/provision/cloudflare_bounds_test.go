package provision

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestCFClientRejectsOversizedProviderResponse(t *testing.T) {
	client := NewCFClient("mock-token")
	client.client.Transport = &mockRoundTripper{
		roundTripFunc: func(req *http.Request) (*http.Response, error) {
			body := strings.Repeat("x", (1<<20)+1)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		},
	}

	if _, err := client.doReq(context.Background(), http.MethodGet, "https://example.test", nil, ""); err == nil {
		t.Fatal("oversized provider response must be rejected")
	}
}
