package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDeployWorkerScriptRetriesIdempotentUpload(t *testing.T) {
	deployer := NewCloudflareDeployer()
	var calls atomic.Int32
	deployer.client.Transport = scannerRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPut {
			t.Fatalf("method=%s, want PUT", req.Method)
		}
		if calls.Add(1) == 1 {
			resp := scannerResponse(http.StatusServiceUnavailable, "later")
			resp.Header.Set("Retry-After", "0")
			return resp, nil
		}
		return scannerResponse(http.StatusNoContent, ""), nil
	})

	if err := deployer.DeployWorkerScript(context.Background(), "user@example.com", "token", "account", "worker", "export default {}"); err != nil {
		t.Fatalf("DeployWorkerScript() error = %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls=%d, want 2", calls.Load())
	}
}

type scannerRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f scannerRoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func scannerResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
