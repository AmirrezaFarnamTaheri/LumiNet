package plugins

import (
	"context"
	"fmt"
	"sync"
)

// HookPoint defines lifecycle execution targets.
type HookPoint string

const (
	HookPreDial    HookPoint = "pre_dial"
	HookPostDial   HookPoint = "post_dial"
	HookPreResolve HookPoint = "pre_resolve"
	HookOnAlert    HookPoint = "on_alert"
)

// Registry manages installed plugins and lifecycle hooks.
type Registry struct {
	mu      sync.RWMutex
	plugins map[string]Plugin
	hooks   map[HookPoint][]Plugin
}

// NewRegistry initializes an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]Plugin),
		hooks:   make(map[HookPoint][]Plugin),
	}
}

// Register adds a plugin into registry under specific hook points.
func (r *Registry) Register(p Plugin, hookPoints ...HookPoint) error {
	if p == nil {
		return fmt.Errorf("nil plugin")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	r.plugins[p.Name()] = p
	for _, hp := range hookPoints {
		r.hooks[hp] = append(r.hooks[hp], p)
	}
	return nil
}

// GetHooks returns all plugins registered for a hook point.
func (r *Registry) GetHooks(hp HookPoint) []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.hooks[hp]
}

// DispatchHook executes all registered plugin hooks for a specific HookPoint.
func (r *Registry) DispatchHook(ctx context.Context, hp HookPoint, eventType string, payload interface{}) {
	plugins := r.GetHooks(hp)
	for _, p := range plugins {
		_ = p.OnEvent(ctx, eventType, payload)
	}
}
