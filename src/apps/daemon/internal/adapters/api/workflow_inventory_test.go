package api

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/maybeknott/luminet/internal/foundation/capabilities"
	"github.com/maybeknott/luminet/internal/foundation/config"
	"github.com/maybeknott/luminet/internal/foundation/store"
	"github.com/maybeknott/luminet/internal/workflows/jobs"
)

func TestRouteWorkflowInventory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "luminet-api-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	st, err := store.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer st.Close()

	if err := st.Migrate(); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	cfgMgr := config.NewManager(filepath.Join(tmpDir, "config.json"))
	jobMgr := jobs.NewJobManager(context.Background(), st)

	serverCfg := &ServerConfig{
		Host:         "127.0.0.1",
		Port:         8080,
		APIKey:       "test-key",
		RateLimitRPS: 100,
	}

	reg := capabilities.NewRegistry()
	server := NewServer(context.Background(), serverCfg, jobMgr, st, cfgMgr, reg)
	routes := server.router.Routes()

	for _, route := range routes {
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			workflow, err := capabilities.GetWorkflowForRoute(route.Method, route.Path)
			if err != nil {
				t.Errorf("route workflow mapping missing or invalid: %v", err)
			} else {
				if workflow == "" {
					t.Errorf("route %s %s mapped to an empty workflow", route.Method, route.Path)
				}
			}
		})
	}
}
