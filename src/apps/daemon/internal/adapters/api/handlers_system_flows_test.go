package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	canonicalprovider "github.com/maybeknott/luminet/internal/analysis/provider"
	"github.com/maybeknott/luminet/internal/foundation/flowregistry"
)

func flowTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	s := &Server{}
	r.GET("/api/system/flows", s.GetSystemFlows)
	r.GET("/api/system/flows/:id", s.GetSystemFlow)
	r.DELETE("/api/system/flows/:id", s.CloseSystemFlow)
	r.POST("/api/system/flows/close", s.CloseSystemFlows)
	return r
}

func TestSystemFlowsFiltersAndReportsPartialCoverage(t *testing.T) {
	reg := flowregistry.Default()
	owner := "api-flow-test-owner"
	if err := reg.DeclareOwner(flowregistry.OwnerCoverage{Owner: owner, Visible: true, Closeable: true, ByteCounters: true, DestinationMetadata: true}); err != nil {
		t.Fatal(err)
	}
	h, err := reg.Register(flowregistry.Descriptor{Owner: owner, Protocol: "test", Destination: "example.test:443"}, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer h.End()
	h.AddUpload(17)

	req := httptest.NewRequest(http.MethodGet, "/api/system/flows?owner="+owner+"&q=example.test&limit=5", nil)
	res := httptest.NewRecorder()
	flowTestRouter().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
	var body flowListResponse
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.CoverageComplete || body.CoverageModel != "participating-runtime-owners-only" {
		t.Fatalf("coverage truth=%+v", body)
	}
	if body.Matched != 1 || body.Returned != 1 || len(body.Flows) != 1 || body.Flows[0].ID != h.ID() {
		t.Fatalf("filtered flows=%+v", body.Flows)
	}
}

func TestSystemFlowCloseDelegatesToOwner(t *testing.T) {
	called := false
	reg := flowregistry.Default()
	if err := reg.DeclareOwner(flowregistry.OwnerCoverage{Owner: "api-close-test", Visible: true, Closeable: true}); err != nil {
		t.Fatal(err)
	}
	h, err := reg.Register(flowregistry.Descriptor{Owner: "api-close-test"}, func(context.Context) error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h.End()

	req := httptest.NewRequest(http.MethodDelete, "/api/system/flows/"+h.ID(), nil)
	res := httptest.NewRecorder()
	flowTestRouter().ServeHTTP(res, req)
	if res.Code != http.StatusOK || !called {
		t.Fatalf("status=%d called=%v body=%s", res.Code, called, res.Body.String())
	}
	if _, ok := flowregistry.Default().Get(h.ID()); ok {
		t.Fatal("successful owner close left flow registered")
	}
}

func TestBulkFlowCloseRequiresExplicitConfirmationAndExplicitIDs(t *testing.T) {
	r := flowTestRouter()
	body := []byte(`{"confirm":false,"ids":["flow-1"]}`)
	res := httptest.NewRecorder()
	r.ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/api/system/flows/close", bytes.NewReader(body)))
	if res.Code != http.StatusPreconditionRequired {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}

	body = []byte(`{"confirm":true,"ids":[]}`)
	res = httptest.NewRecorder()
	r.ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/api/system/flows/close", bytes.NewReader(body)))
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
}

func TestSystemFlowsAddsLocalProviderCorpusAttribution(t *testing.T) {
	if err := canonicalprovider.DefaultService.InitializeBuiltin(); err != nil {
		t.Fatal(err)
	}
	reg := flowregistry.Default()
	owner := "api-provider-attribution-test"
	if err := reg.DeclareOwner(flowregistry.OwnerCoverage{Owner: owner, Visible: true, DestinationMetadata: true}); err != nil {
		t.Fatal(err)
	}
	h, err := reg.Register(flowregistry.Descriptor{Owner: owner, Destination: "104.16.10.20:443"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.End()

	req := httptest.NewRequest(http.MethodGet, "/api/system/flows?owner="+owner, nil)
	res := httptest.NewRecorder()
	flowTestRouter().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
	var body flowListResponse
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Flows) != 1 || body.Flows[0].DestinationProvider == nil || body.Flows[0].DestinationProvider.ProviderID != "cloudflare" {
		t.Fatalf("flows=%+v", body.Flows)
	}
}
