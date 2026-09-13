package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/foundation/config"
	"github.com/maybeknott/luminet/internal/foundation/secrets"
)

type testNativeSecretStore struct {
	values map[string][]byte
}

func newTestNativeSecretStore() *testNativeSecretStore {
	return &testNativeSecretStore{values: make(map[string][]byte)}
}

func (s *testNativeSecretStore) ProviderName() string { return "test-native" }
func (s *testNativeSecretStore) Native() bool          { return true }
func (s *testNativeSecretStore) Put(_ context.Context, ref string, value []byte) error {
	s.values[ref] = append([]byte(nil), value...)
	return nil
}
func (s *testNativeSecretStore) Get(_ context.Context, ref string) ([]byte, error) {
	value, ok := s.values[ref]
	if !ok {
		return nil, secrets.ErrNotFound{Ref: ref}
	}
	return append([]byte(nil), value...), nil
}
func (s *testNativeSecretStore) Delete(_ context.Context, ref string) error {
	delete(s.values, ref)
	return nil
}
func (s *testNativeSecretStore) List(_ context.Context) ([]string, error) {
	refs := make([]string, 0, len(s.values))
	for ref := range s.values {
		refs = append(refs, ref)
	}
	return refs, nil
}

func TestListProxyNodesDoesNotSerializePasswords(t *testing.T) {
	gin.SetMode(gin.TestMode)
	manager := config.NewManagerWithSecretStore(filepath.Join(t.TempDir(), "config.json"), newTestNativeSecretStore())
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
