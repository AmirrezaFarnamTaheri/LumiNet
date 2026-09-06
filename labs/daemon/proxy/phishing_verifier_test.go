package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPhishingVerifierMalicious(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(PhishingResponse{Match: true})
	}))
	defer mockServer.Close()

	verifier := GetPhishingVerifier()
	verifier.SetCheckURL(mockServer.URL)

	isMalicious, err := verifier.IsMalicious(context.Background(), "scam-domain.com")
	if err != nil {
		t.Fatalf("Phishing check failed: %v", err)
	}

	if !isMalicious {
		t.Error("Expected scam-domain.com to be flagged as malicious")
	}
}

func TestPhishingVerifierSafe(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(PhishingResponse{Match: false})
	}))
	defer mockServer.Close()

	verifier := GetPhishingVerifier()
	verifier.SetCheckURL(mockServer.URL)

	isMalicious, err := verifier.IsMalicious(context.Background(), "google.com")
	if err != nil {
		t.Fatalf("Phishing check failed: %v", err)
	}

	if isMalicious {
		t.Error("Expected google.com to be flagged as safe")
	}
}
