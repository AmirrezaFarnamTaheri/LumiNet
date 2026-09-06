package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestFptnCompatibilityRoutesFailClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := &Server{}
	router := gin.New()
	server.setupFptnRoutes(router.Group("/api"))

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/fptn/dns"},
		{http.MethodPost, "/api/fptn/login"},
		{http.MethodGet, "/api/fptn/test_file.bin"},
		{http.MethodGet, "/api/fptn/tunnel"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req)
		if res.Code != http.StatusNotImplemented {
			t.Fatalf("%s %s status=%d want=%d", tc.method, tc.path, res.Code, http.StatusNotImplemented)
		}
		if body := res.Body.String(); !strings.Contains(body, `"supported":false`) || !strings.Contains(body, "FPTN") {
			t.Fatalf("%s %s returned non-truthful body %s", tc.method, tc.path, body)
		}
	}
}
