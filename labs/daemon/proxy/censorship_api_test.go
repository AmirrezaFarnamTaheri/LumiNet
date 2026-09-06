package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCensorshipAPI(t *testing.T) {
	api := NewCensorshipAPI("127.0.0.1:1080")

	t.Run("GetCensoredDomains", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/censored-domains", nil)
		rec := httptest.NewRecorder()
		api.GetCensoredDomainsHandler(rec, req)

		resp := rec.Result()
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got: %d", resp.StatusCode)
		}

		var domains []string
		_ = json.NewDecoder(resp.Body).Decode(&domains)

		if len(domains) == 0 {
			t.Error("expected non-empty domain list")
		}

		hasYoutube := false
		for _, d := range domains {
			if d == "youtube.com" {
				hasYoutube = true
				break
			}
		}
		if !hasYoutube {
			t.Error("missing youtube.com in censored domain list")
		}
	})

	t.Run("ReportBlock", func(t *testing.T) {
		payload := `{"domain":"new-blocked-site.org"}`
		req := httptest.NewRequest("POST", "/api/report-block", bytes.NewBufferString(payload))
		rec := httptest.NewRecorder()
		api.ReportBlockHandler(rec, req)

		resp := rec.Result()
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			t.Errorf("expected 201, got: %d", resp.StatusCode)
		}

		// Verify added to list
		api.mu.RLock()
		isBlocked := api.blockedDomains["new-blocked-site.org"]
		api.mu.RUnlock()

		if !isBlocked {
			t.Error("expected reported domain to be added to blocked list")
		}
	})

	t.Run("GetPacFile", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/proxy.pac", nil)
		rec := httptest.NewRecorder()
		api.GetPacFileHandler(rec, req)

		resp := rec.Result()
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got: %d", resp.StatusCode)
		}

		bodyBytes, _ := io.ReadAll(resp.Body)
		body := string(bodyBytes)

		if !strings.Contains(body, "FindProxyForURL") || !strings.Contains(body, "SOCKS5 127.0.0.1:1080") {
			t.Errorf("invalid PAC file body: %s", body)
		}
	})
}
