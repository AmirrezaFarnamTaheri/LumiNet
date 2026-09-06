package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/integrations/sub"
)

func TestSubscriptionProfileRoutesRequireExplicitRemoteFetchOptIn(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := &Server{profileService: sub.NewProfileService()}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	defer server.profileService.Close(shutdownCtx)
	router := gin.New()
	server.setupSubscriptionRoutes(router.Group("/api"))

	body := []byte(`{"name":"Local profile","url":"https://subscription.example/sub","auto_refresh":true}`)
	writer := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/subscriptions/profiles", bytes.NewReader(body))
	router.ServeHTTP(writer, request)
	if writer.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", writer.Code, writer.Body.String())
	}
	var profile SubscriptionProfile
	if err := json.Unmarshal(writer.Body.Bytes(), &profile); err != nil {
		t.Fatal(err)
	}
	if profile.RemoteFetchEnabled {
		t.Fatalf("remote fetch enabled without opt-in: %+v", profile)
	}
	if !profile.AutoRefresh {
		t.Fatalf("auto-refresh preference was not persisted: %+v", profile)
	}
	if !profile.LastUpdated.IsZero() {
		t.Fatalf("new profile reports a refresh before any fetch completed: %s", profile.LastUpdated)
	}

	writer = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/api/subscriptions/profiles/"+profile.ID, nil)
	router.ServeHTTP(writer, request)
	if writer.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", writer.Code, writer.Body.String())
	}
}
