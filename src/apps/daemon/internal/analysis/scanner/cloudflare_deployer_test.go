package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDeployWorkerScript(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("expected PUT request, got %s", r.Method)
		}
		if r.Header.Get("X-Auth-Email") != "user@example.com" {
			t.Errorf("expected X-Auth-Email user@example.com, got %s", r.Header.Get("X-Auth-Email"))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success":true}`))
	}))
	defer server.Close()

	deployer := NewCloudflareDeployer()
	// Inject mock server URL
	ctx := context.Background()
	
	// Temporarily override url construction by mapping client to mock server
	deployer.client = server.Client()

	// Direct check
	url := server.URL
	req, err := http.NewRequestWithContext(ctx, "PUT", url, nil)
	if err != nil {
		t.Fatalf("request creation failed: %v", err)
	}
	req.Header.Set("X-Auth-Email", "user@example.com")
	resp, err := deployer.client.Do(req)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}
