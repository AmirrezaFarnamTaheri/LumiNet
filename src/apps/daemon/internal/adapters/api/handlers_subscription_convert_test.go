package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
)

func conversionTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	s := &Server{}
	r.POST("/api/subscriptions/convert", s.ConvertSubscriptionHandler)
	return r
}

func TestSubscriptionConversionIsLocalOnlyAndDoesNotFetchURLShapedContent(t *testing.T) {
	var hits atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	defer remote.Close()

	payload, _ := json.Marshal(map[string]any{
		"content": remote.URL + "#local-http-proxy",
		"target":  "luminet-json",
	})
	res := httptest.NewRecorder()
	conversionTestRouter().ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/api/subscriptions/convert", bytes.NewReader(payload)))
	if res.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("conversion fetched URL-shaped content: hits=%d", got)
	}
	var resp map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	contentStr, _ := resp["content"].(string)
	if !strings.Contains(contentStr, `"schema": "luminet.proxy-bundle.v1"`) && !bytes.Contains(res.Body.Bytes(), []byte(`luminet.proxy-bundle.v1`)) {
		t.Fatalf("missing canonical bundle: %s", res.Body.String())
	}
}

func TestSubscriptionConversionDefaultsStrictAndReturnsCompatibilityEvidence(t *testing.T) {
	content := "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=xhttp&security=tls&mode=packet-up#xhttp"
	payload, _ := json.Marshal(map[string]any{"content": content, "target": "clash-meta"})
	res := httptest.NewRecorder()
	conversionTestRouter().ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/api/subscriptions/convert", bytes.NewReader(payload)))
	if res.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	result, ok := body["result"].(map[string]any)
	if !ok {
		t.Fatalf("missing result evidence: %#v", body)
	}
	report, ok := result["report"].(map[string]any)
	if !ok || report["unsupported"].(float64) < 1 {
		t.Fatalf("missing unsupported report: %#v", result)
	}
}

func TestSubscriptionConversionRejectsOversizedBodyBeforeParsing(t *testing.T) {
	body := bytes.Repeat([]byte("x"), int(maxLocalConversionRequestBytes)+1024)
	request := fmt.Sprintf(`{"content":"%s","target":"luminet-json"}`, body)
	res := httptest.NewRecorder()
	conversionTestRouter().ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/api/subscriptions/convert", bytes.NewBufferString(request)))
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body-prefix=%q", res.Code, res.Body.String()[:minInt(len(res.Body.String()), 200)])
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
