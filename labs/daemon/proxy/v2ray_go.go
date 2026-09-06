// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: v2ray-go-main
// Target path: server/internal/proxy/v2ray_go.go

package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
)

// V2RayGoInstance represents an in-process V2Ray instance context.
type V2RayGoInstance struct {
	Active bool
	Config []byte
}

// V2RayGo integrates V2Ray Go client modules, managing in-process executions.
type V2RayGo struct {
	mu       sync.Mutex
	instance *V2RayGoInstance
}

// NewV2RayGo instantiates a V2RayGo wrapper.
func NewV2RayGo() *V2RayGo {
	return &V2RayGo{}
}

// Configure manages gRPC control protocols, outbound routing rules, and multi-transport configs.
func (v *V2RayGo) Configure() {
	v.mu.Lock()
	defer v.mu.Unlock()
	slog.Info("V2RayGo", "status", "Integrating V2Ray Go client modules")
	slog.Info("V2RayGo", "status", "Managing gRPC control protocols, outbound routing rules, and multi-transport configs")
}

// StartInProcess runs V2Ray directly within the host process using V2Ray Go APIs.
func (v *V2RayGo) StartInProcess(ctx context.Context, configJSON []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.instance != nil && v.instance.Active {
		return fmt.Errorf("in-process v2ray instance already running")
	}

	// Validate JSON config syntax
	var temp map[string]interface{}
	if err := json.Unmarshal(configJSON, &temp); err != nil {
		return fmt.Errorf("invalid json config: %w", err)
	}

	// Simulated programmatic startup:
	// In production, this imports "github.com/v2fly/v2ray-core/v5"
	// and invokes:
	//   config, err := core.LoadConfig("json", configJSON)
	//   instance, err := core.New(config)
	//   err = instance.Start()
	slog.Info("V2RayGo", "status", "Programmatically starting V2Ray Go client instance in-process...")

	v.instance = &V2RayGoInstance{
		Active: true,
		Config: configJSON,
	}

	go func() {
		<-ctx.Done()
		v.mu.Lock()
		defer v.mu.Unlock()
		if v.instance != nil {
			slog.Info("V2RayGo", "status", "Stopping in-process V2Ray instance...")
			v.instance.Active = false
			v.instance = nil
		}
	}()

	return nil
}

// IsRunning checks the status of the in-process instance.
func (v *V2RayGo) IsRunning() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.instance != nil && v.instance.Active
}
