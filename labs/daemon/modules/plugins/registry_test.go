package plugins

import (
	"context"
	"testing"
)

type mockPlugin struct{ name string }

func (m *mockPlugin) Name() string                                              { return m.name }
func (m *mockPlugin) Version() string                                           { return "1.0.0" }
func (m *mockPlugin) Init(ctx context.Context) error                            { return nil }
func (m *mockPlugin) OnEvent(ctx context.Context, eventType string, payload interface{}) error { return nil }
func (m *mockPlugin) Stop() error                                               { return nil }

func TestPluginRegistry(t *testing.T) {
	reg := NewRegistry()
	p := &mockPlugin{name: "test-plugin"}

	if err := reg.Register(p, HookPreDial, HookOnAlert); err != nil {
		t.Fatalf("failed to register plugin: %v", err)
	}

	preDialHooks := reg.GetHooks(HookPreDial)
	if len(preDialHooks) != 1 {
		t.Fatalf("expected 1 pre_dial hook, got %d", len(preDialHooks))
	}
	if preDialHooks[0].Name() != "test-plugin" {
		t.Errorf("expected test-plugin, got %s", preDialHooks[0].Name())
	}
}
