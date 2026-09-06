package provision

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCloudflareDNSCreateReconcilesBeforeReplay(t *testing.T) {
	client := NewCFClient("mock-token")
	var calls atomic.Int32
	var creates atomic.Int32
	client.client.Transport = &retryRoundTripper{roundTripFunc: func(req *http.Request) (*http.Response, error) {
		switch calls.Add(1) {
		case 1:
			if req.Method != http.MethodGet {
				t.Fatalf("first request method=%s, want GET", req.Method)
			}
			return cloudflareTestResponse(http.StatusOK, `{"success":true,"result":[]}`), nil
		case 2:
			if req.Method != http.MethodPost {
				t.Fatalf("second request method=%s, want POST", req.Method)
			}
			creates.Add(1)
			return nil, errors.New("connection reset after write")
		case 3:
			if req.Method != http.MethodGet {
				t.Fatalf("reconciliation method=%s, want GET", req.Method)
			}
			return cloudflareTestResponse(http.StatusOK, `{"success":true,"result":[{"id":"record-1","type":"A","name":"vpn.example.com","content":"203.0.113.7","proxied":true}]}`), nil
		default:
			t.Fatalf("unexpected extra request %d: %s %s", calls.Load(), req.Method, req.URL)
			return nil, nil
		}
	}}

	if err := client.UpsertDNSRecord(context.Background(), "zone-1", "vpn.example.com", "203.0.113.7", true); err != nil {
		t.Fatalf("UpsertDNSRecord() error = %v", err)
	}
	if creates.Load() != 1 {
		t.Fatalf("create calls=%d, want exactly 1", creates.Load())
	}
}

func TestCloudflareDNSCreateFailsClosedOnConflictingReadback(t *testing.T) {
	client := NewCFClient("mock-token")
	var calls atomic.Int32
	client.client.Transport = &retryRoundTripper{roundTripFunc: func(req *http.Request) (*http.Response, error) {
		switch calls.Add(1) {
		case 1:
			return cloudflareTestResponse(http.StatusOK, `{"success":true,"result":[]}`), nil
		case 2:
			return nil, errors.New("timeout after write")
		case 3:
			return cloudflareTestResponse(http.StatusOK, `{"success":true,"result":[{"id":"record-1","type":"A","name":"vpn.example.com","content":"198.51.100.9","proxied":true}]}`), nil
		default:
			t.Fatalf("unexpected replay after conflicting reconciliation")
			return nil, nil
		}
	}}

	err := client.UpsertDNSRecord(context.Background(), "zone-1", "vpn.example.com", "203.0.113.7", true)
	if err == nil || !strings.Contains(err.Error(), "state uncertain") || !strings.Contains(err.Error(), "does not match desired state") {
		t.Fatalf("error=%v, want fail-closed conflicting reconciliation", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("calls=%d, want 3 without replay", calls.Load())
	}
}

func cloudflareTestResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

type retryRoundTripper struct {
	roundTripFunc func(*http.Request) (*http.Response, error)
}

func (r *retryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return r.roundTripFunc(req)
}
