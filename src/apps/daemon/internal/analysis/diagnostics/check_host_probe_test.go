package diagnostics

import (
	"testing"
)

func TestBuildCheckHostURL(t *testing.T) {
	url, err := BuildCheckHostURL("1.1.1.1", "ping", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !stringsContains(url, "https://check-host.net/check-ping?host=1.1.1.1") {
		t.Errorf("url should target check-ping, got %s", url)
	}
	for _, n := range CanonicalIranNodes {
		if !stringsContains(url, "&node="+n) {
			t.Errorf("missing node %s in url: %s", n, url)
		}
	}

	httpURL, err := BuildCheckHostURL("example.com", "http", []string{"ir1.node.check-host.net"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !stringsContains(httpURL, "https://check-host.net/check-http?host=example.com&node=ir1.node.check-host.net") {
		t.Errorf("unexpected http url: %s", httpURL)
	}

	_, err = BuildCheckHostURL("example.com", "invalid_method", nil)
	if err == nil {
		t.Errorf("expected error for invalid method")
	}
}

func TestParseInitiateResponse(t *testing.T) {
	okPayload := []byte(`{"ok": 1, "request_id": "test.req.123", "permanent_link": "https://check-host.net/check-result/test.req.123"}`)
	reqID, err := ParseInitiateResponse(okPayload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqID != "test.req.123" {
		t.Errorf("expected test.req.123, got %s", reqID)
	}

	errPayload := []byte(`{"ok": 0, "error": "Unable to resolve host"}`)
	_, err = ParseInitiateResponse(errPayload)
	if err == nil {
		t.Errorf("expected error from failed initiate payload")
	}
}

func TestParseResultResponsePing(t *testing.T) {
	payload := []byte(`{
		"ir1.node.check-host.net": [[
			["OK", 0.045],
			["OK", 0.043]
		]],
		"ir2.node.check-host.net": [[
			["OK", 0.050]
		]],
		"ir3.node.check-host.net": [[
			["TIMEOUT", 0.0]
		]]
	}`)

	assessment, err := ParseResultResponse(payload, "8.8.8.8", "ping")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if assessment.TotalNodes != 3 {
		t.Errorf("expected 3 nodes, got %d", assessment.TotalNodes)
	}
	if assessment.ResponsiveNodes != 2 {
		t.Errorf("expected 2 responsive, got %d", assessment.ResponsiveNodes)
	}
	if assessment.BlockedNodes != 1 {
		t.Errorf("expected 1 blocked, got %d", assessment.BlockedNodes)
	}
	if assessment.AvgRTTMs == nil || *assessment.AvgRTTMs <= 0 {
		t.Errorf("expected valid average RTT")
	}
	if !assessment.IsReady {
		t.Errorf("expected assessment to be ready")
	}
}

func TestParseResultResponseHTTPBlocked(t *testing.T) {
	payload := []byte(`{
		"ir1.node.check-host.net": [[0, 5.0, "Connection timed out", null, null]],
		"ir2.node.check-host.net": [[0, 5.0, "Connection timed out", null, null]],
		"ir3.node.check-host.net": [[0, 2.5, "Connection reset by peer", null, null]]
	}`)

	assessment, err := ParseResultResponse(payload, "twitter.com", "http")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if assessment.ResponsiveNodes != 0 {
		t.Errorf("expected 0 responsive, got %d", assessment.ResponsiveNodes)
	}
	if assessment.BlockedNodes != 3 {
		t.Errorf("expected 3 blocked, got %d", assessment.BlockedNodes)
	}
	if assessment.Verdict != VerdictFiltered {
		t.Errorf("expected verdict filtered, got %s", assessment.Verdict)
	}
}

func TestParseResultResponseDNS(t *testing.T) {
	payload := []byte(`{
		"ir1.node.check-host.net": [{"A": ["93.184.216.34"], "TTL": 300}],
		"ir2.node.check-host.net": [{"A": ["10.10.34.34"], "TTL": 60}]
	}`)

	assessment, err := ParseResultResponse(payload, "example.com", "dns")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if assessment.ResponsiveNodes != 2 {
		t.Errorf("expected 2 responsive, got %d", assessment.ResponsiveNodes)
	}
	if assessment.Verdict != VerdictClean {
		t.Errorf("expected verdict clean, got %s", assessment.Verdict)
	}
}

func stringsContains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || (len(s) > 0 && len(substr) > 0 && searchSubstring(s, substr)))
}

func searchSubstring(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
