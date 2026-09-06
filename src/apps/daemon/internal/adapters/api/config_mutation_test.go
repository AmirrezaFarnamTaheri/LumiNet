package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/foundation/config"
)

func TestParseConfigRevisionETag(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want uint64
		ok   bool
	}{
		{name: "zero", raw: `"cfg-0"`, want: 0, ok: true},
		{name: "revision", raw: `"cfg-42"`, want: 42, ok: true},
		{name: "trim space", raw: `  "cfg-7"  `, want: 7, ok: true},
		{name: "unquoted", raw: `cfg-7`, ok: false},
		{name: "wrong prefix", raw: `"rev-7"`, ok: false},
		{name: "empty revision", raw: `"cfg-"`, ok: false},
		{name: "negative", raw: `"cfg--1"`, ok: false},
		{name: "weak", raw: `W/"cfg-7"`, ok: false},
		{name: "list", raw: `"cfg-7", "cfg-8"`, ok: false},
		{name: "wildcard", raw: `*`, ok: false},
		{name: "overflow", raw: `"cfg-18446744073709551616"`, ok: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseConfigRevisionETag(test.raw)
			if test.ok && err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if !test.ok && err == nil {
				t.Fatalf("parse succeeded with %d, want rejection", got)
			}
			if test.ok && got != test.want {
				t.Fatalf("revision=%d, want %d", got, test.want)
			}
		})
	}
}

func TestConfigRevisionConflictStatus(t *testing.T) {
	if got := configRevisionConflictStatus(`"cfg-7"`); got != 412 {
		t.Fatalf("If-Match conflict status=%d, want 412", got)
	}
	if got := configRevisionConflictStatus(""); got != 409 {
		t.Fatalf("snapshot/body conflict status=%d, want 409", got)
	}
}

func TestConfigMutationOptionsAutomaticRetryWithoutClientPrecondition(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodPost, "/config", nil)

	options, ok := configMutationOptions(ctx, 0)
	if !ok {
		t.Fatal("configMutationOptions rejected implicit server-owned mutation")
	}
	if options.ExpectedRevision != nil {
		t.Fatalf("ExpectedRevision=%v, want nil for automatic replay", *options.ExpectedRevision)
	}
	if options.MaxAttempts != config.DefaultMutationAttempts {
		t.Fatalf("MaxAttempts=%d, want %d", options.MaxAttempts, config.DefaultMutationAttempts)
	}
}

func TestConfigMutationOptionsExplicitPreconditionsArePinned(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Run("body revision", func(t *testing.T) {
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		ctx.Request = httptest.NewRequest(http.MethodPost, "/config", nil)
		options, ok := configMutationOptions(ctx, 12)
		if !ok || options.ExpectedRevision == nil || *options.ExpectedRevision != 12 {
			t.Fatalf("options=%+v ok=%v, want explicit body revision 12", options, ok)
		}
	})

	t.Run("if-match overrides body", func(t *testing.T) {
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		ctx.Request = httptest.NewRequest(http.MethodPost, "/config", nil)
		ctx.Request.Header.Set("If-Match", `"cfg-19"`)
		options, ok := configMutationOptions(ctx, 12)
		if !ok || options.ExpectedRevision == nil || *options.ExpectedRevision != 19 {
			t.Fatalf("options=%+v ok=%v, want If-Match revision 19", options, ok)
		}
	})
}

func TestConfigMutationOptionsRejectsMalformedIfMatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	response := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(response)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/config", nil)
	ctx.Request.Header.Set("If-Match", "cfg-19")
	if _, ok := configMutationOptions(ctx, 0); ok {
		t.Fatal("malformed If-Match accepted")
	}
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want %d", response.Code, http.StatusBadRequest)
	}
}
