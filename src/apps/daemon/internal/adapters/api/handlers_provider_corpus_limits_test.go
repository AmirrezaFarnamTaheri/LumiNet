package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestProviderCorpusUploadRejectsOversizedBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := &Server{}
	router := gin.New()
	server.setupProviderCorpusRoutes(router.Group("/api"))

	body := bytes.Repeat([]byte("x"), int(maxProviderCorpusUploadBytes)+1)
	request := httptest.NewRequest(http.MethodPost, "/api/provider-corpus", bytes.NewReader(body))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusRequestEntityTooLarge, response.Body.String())
	}
	if got := response.Body.String(); !bytes.Contains([]byte(got), []byte("PROVIDER_CORPUS_TOO_LARGE")) {
		t.Fatalf("response does not contain stable oversized error: %s", got)
	}
}
