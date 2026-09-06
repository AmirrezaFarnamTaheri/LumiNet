package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunSpeedtestMeasuresLatencyLossAndDownload(t *testing.T) {
	var probes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") == "bytes=0-0" {
			n := probes.Add(1)
			if n == 3 {
				http.Error(w, "probe failure", http.StatusServiceUnavailable)
				return
			}
			time.Sleep(time.Duration(n) * time.Millisecond)
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write([]byte{0})
			return
		}

		w.Header().Set("Server-Timing", "dur=1")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(make([]byte, 16*1024))
	}))
	defer server.Close()

	result, status := runSpeedtest(context.Background(), SpeedtestRequest{
		URL:            server.URL,
		Bytes:          16 * 1024,
		TimeoutSeconds: 5,
		LatencySamples: 5,
	})
	if status != http.StatusOK || !result.Success {
		t.Fatalf("runSpeedtest status=%d result=%+v", status, result)
	}
	if result.LatencySamples != 5 || result.LatencySuccessfulSamples != 4 {
		t.Fatalf("unexpected sample counts: %+v", result)
	}
	if result.PacketLossPercent != 20 {
		t.Fatalf("packet loss=%v, want 20", result.PacketLossPercent)
	}
	if result.DownloadSpeedMbps <= 0 {
		t.Fatalf("download speed=%v, want >0", result.DownloadSpeedMbps)
	}
	if result.QualityStable {
		t.Fatal("20% packet loss must classify the quality as unstable")
	}
}

func TestRunSpeedtestRequestBounds(t *testing.T) {
	cases := []SpeedtestRequest{
		{URL: "ftp://example.com/file"},
		{URL: "http://user:pass@example.com/file"},
		{URL: "http://example.com", Bytes: maxSpeedtestBytes + 1},
		{URL: "http://example.com", TimeoutSeconds: maxSpeedtestTimeoutSeconds + 1},
		{URL: "http://example.com", LatencySamples: maxSpeedtestLatencySamples + 1},
		{URL: "http://example.com", Proxy: "file:///tmp/proxy"},
	}
	for _, req := range cases {
		result, status := runSpeedtest(context.Background(), req)
		if status != http.StatusBadRequest || result.Success || result.Error == "" {
			t.Fatalf("invalid request was not rejected: req=%+v status=%d result=%+v", req, status, result)
		}
	}
}

func TestRunSpeedtestRejectsOriginThatIgnoresDownloadBudget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") == "bytes=0-0" {
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write([]byte{0})
			return
		}
		// Deliberately ignore Range and stream beyond the approved budget.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, 2049))
	}))
	defer server.Close()

	result, status := runSpeedtest(context.Background(), SpeedtestRequest{
		URL:            server.URL,
		Bytes:          2048,
		TimeoutSeconds: 5,
		LatencySamples: 1,
	})
	if status != http.StatusBadGateway || result.Success {
		t.Fatalf("oversized origin response status=%d result=%+v", status, result)
	}
}

func TestRunSpeedtestBoundsRedirectChain(t *testing.T) {
	server := httptest.NewServer(nil)
	defer server.Close()
	redirects := atomic.Int32{}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") == "bytes=0-0" {
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write([]byte{0})
			return
		}
		n := redirects.Add(1)
		if n <= maxSpeedtestRedirects+1 {
			http.Redirect(w, r, server.URL, http.StatusTemporaryRedirect)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	result, status := runSpeedtest(context.Background(), SpeedtestRequest{
		URL:            server.URL,
		Bytes:          1024,
		TimeoutSeconds: 5,
		LatencySamples: 1,
	})
	if status != http.StatusBadGateway || result.Success {
		t.Fatalf("redirect chain status=%d result=%+v", status, result)
	}
}

func TestRunSpeedtestHonorsParentCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(500 * time.Millisecond):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte{0})
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	result, status := runSpeedtest(ctx, SpeedtestRequest{
		URL:            server.URL,
		Bytes:          1024,
		TimeoutSeconds: 5,
		LatencySamples: 1,
	})
	if status != http.StatusBadGateway || result.Success {
		t.Fatalf("canceled run status=%d result=%+v", status, result)
	}
}
