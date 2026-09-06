package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestSetecClient(t *testing.T) {
	var queryCount int32

	// Setup mock secrets server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token != "Bearer my-secret-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if r.URL.Path == "/v1/secrets/db_password" {
			atomic.AddInt32(&queryCount, 1)
			resp := setecResponse{
				Value: "db-secret-pass-999",
				TTL:   2, // 2 seconds TTL
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewSetecClient(server.URL, "my-secret-token")

	// 1. Fetch first time (cache miss)
	val, err := client.GetSecret("db_password")
	if err != nil {
		t.Fatalf("failed to fetch secret: %v", err)
	}

	if val != "db-secret-pass-999" {
		t.Errorf("unexpected secret value: %s", val)
	}

	if atomic.LoadInt32(&queryCount) != 1 {
		t.Errorf("expected server query count to be 1, got %d", queryCount)
	}

	// 2. Fetch second time immediately (should hit cache)
	val2, err := client.GetSecret("db_password")
	if err != nil {
		t.Fatalf("failed to fetch secret: %v", err)
	}

	if val2 != "db-secret-pass-999" {
		t.Errorf("unexpected secret value: %s", val2)
	}

	// Server query count must STILL be 1 due to caching
	if atomic.LoadInt32(&queryCount) != 1 {
		t.Errorf("expected server query count to remain 1 (cache hit), got %d", queryCount)
	}

	// 3. Unauthorized access test
	badClient := NewSetecClient(server.URL, "wrong-token")
	_, err = badClient.GetSecret("db_password")
	if err == nil {
		t.Error("expected unauthorized request to fail")
	}
}
