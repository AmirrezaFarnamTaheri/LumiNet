package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/foundation/config"
)

func TestListProxyNodesDoesNotSerializePasswords(t *testing.T) {
	gin.SetMode(gin.TestMode)
	manager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	_, revision := manager.GetWithRevision()
	if _, err := manager.SaveIfRevision(&config.Config{ProxyNodes: []config.ProxyNodeConfig{{
		ID: "node-1", Host: "proxy.example", Port: 443, Type: "trojan", Auth: true, Username: "operator", Password: "top-secret",
	}}}, revision); err != nil {
		t.Fatal(err)
	}
	server := &Server{configManager: manager}
	router := gin.New()
	router.GET("/proxies", server.ListProxyNodes)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/proxies", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	if got := response.Body.String(); strings.Contains(got, "top-secret") {
		t.Fatalf("response exposed proxy password: %s", got)
	}
	var nodes []struct {
		HasPassword bool `json:"has_password"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &nodes); err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || !nodes[0].HasPassword {
		t.Fatalf("password-presence contract = %#v", nodes)
	}
}
