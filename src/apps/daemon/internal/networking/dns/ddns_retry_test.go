package dns

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDuckDNSRetriesRetryableMutation(t *testing.T) {
	u := NewUpdater("duckdns", "token", "example")
	var calls atomic.Int32
	u.httpClient.Transport = ddnsRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet {
			t.Fatalf("method=%s, want GET", req.Method)
		}
		if calls.Add(1) == 1 {
			resp := ddnsTestResponse(http.StatusServiceUnavailable, "later")
			resp.Header.Set("Retry-After", "0")
			return resp, nil
		}
		return ddnsTestResponse(http.StatusOK, "OK"), nil
	})

	result, err := u.UpdateIP(context.Background(), "203.0.113.8")
	if err != nil {
		t.Fatalf("UpdateIP() error = %v", err)
	}
	if !result.Updated || calls.Load() != 2 {
		t.Fatalf("result=%+v calls=%d, want updated with 2 attempts", result, calls.Load())
	}
}

func TestDuckDNSRejectsFinalHTTPFailure(t *testing.T) {
	u := NewUpdater("duckdns", "token", "example")
	u.httpClient.Transport = ddnsRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return ddnsTestResponse(http.StatusUnauthorized, "bad token"), nil
	})

	_, err := u.UpdateIP(context.Background(), "203.0.113.8")
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("error=%v, want HTTP 401 failure", err)
	}
}

type ddnsRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f ddnsRoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func ddnsTestResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
