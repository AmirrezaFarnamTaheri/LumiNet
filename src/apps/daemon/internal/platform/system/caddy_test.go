package system

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type configTestPlugin struct {
	name         string
	provisionErr error
	startErr     error
	stopErr      error
	startGate    <-chan struct{}

	provisioned atomic.Int32
	started     atomic.Int32
	stopped     atomic.Int32
	lastConfig  json.RawMessage
	mu          sync.Mutex
}

func (p *configTestPlugin) Name() string { return p.name }

func (p *configTestPlugin) Provision(raw json.RawMessage) error {
	p.provisioned.Add(1)
	p.mu.Lock()
	p.lastConfig = append(json.RawMessage(nil), raw...)
	p.mu.Unlock()
	return p.provisionErr
}

func (p *configTestPlugin) Start() error {
	p.started.Add(1)
	if p.startGate != nil {
		<-p.startGate
	}
	return p.startErr
}

func (p *configTestPlugin) Stop() error {
	p.stopped.Add(1)
	return p.stopErr
}

func isolatePluginRegistry(t *testing.T) {
	t.Helper()
	pluginRegistryMu.Lock()
	previous := pluginRegistry
	pluginRegistry = make(map[string]func() Plugin)
	pluginRegistryMu.Unlock()
	t.Cleanup(func() {
		pluginRegistryMu.Lock()
		pluginRegistry = previous
		pluginRegistryMu.Unlock()
	})
}

func TestConfigManagerSemanticHashAndUnchangedPluginReuse(t *testing.T) {
	isolatePluginRegistry(t)

	var created atomic.Int32
	var first *configTestPlugin
	RegisterPlugin("alpha", func() Plugin {
		p := &configTestPlugin{name: "alpha"}
		if created.Add(1) == 1 {
			first = p
		}
		return p
	})

	cm := NewConfigManager()
	if err := cm.HotReload([]byte(`{
		"proxy_port":1080,
		"plugins":{"alpha":{"b":2,"a":1}}
	}`)); err != nil {
		t.Fatalf("initial reload: %v", err)
	}
	initialHash := cm.ActiveHash()

	// Formatting and object-key order are semantic no-ops.
	err := cm.HotReload([]byte(`{"plugins":{"alpha":{"a":1,"b":2}},"proxy_port":1080}`))
	if !errors.Is(err, ErrConfigUnchanged) {
		t.Fatalf("expected ErrConfigUnchanged, got %v", err)
	}
	if cm.ActiveHash() != initialHash {
		t.Fatal("semantic no-op changed active hash")
	}
	if got := created.Load(); got != 1 {
		t.Fatalf("semantic no-op created %d plugin instances, want 1", got)
	}

	// A top-level change must commit without recreating an unchanged plugin.
	if err := cm.HotReload([]byte(`{"proxy_port":1081,"plugins":{"alpha":{"a":1,"b":2}}}`)); err != nil {
		t.Fatalf("top-level reload: %v", err)
	}
	if got := created.Load(); got != 1 {
		t.Fatalf("unchanged plugin was recreated: constructors=%d", got)
	}
	if first.stopped.Load() != 0 {
		t.Fatalf("unchanged plugin was stopped %d times", first.stopped.Load())
	}
	if cm.loadedPlugins["alpha"] != first {
		t.Fatal("unchanged plugin instance was not reused")
	}
}

func TestConfigManagerChangedPluginReplacesAndRetiresOldGeneration(t *testing.T) {
	isolatePluginRegistry(t)

	var instances []*configTestPlugin
	RegisterPlugin("alpha", func() Plugin {
		p := &configTestPlugin{name: "alpha"}
		instances = append(instances, p)
		return p
	})

	cm := NewConfigManager()
	if err := cm.HotReload([]byte(`{"plugins":{"alpha":{"version":1}}}`)); err != nil {
		t.Fatalf("initial reload: %v", err)
	}
	if err := cm.HotReload([]byte(`{"plugins":{"alpha":{"version":2}}}`)); err != nil {
		t.Fatalf("changed reload: %v", err)
	}
	if len(instances) != 2 {
		t.Fatalf("constructed %d instances, want 2", len(instances))
	}
	if instances[0].stopped.Load() != 1 {
		t.Fatalf("old generation stop count=%d, want 1", instances[0].stopped.Load())
	}
	if instances[1].stopped.Load() != 0 {
		t.Fatalf("new generation unexpectedly stopped %d times", instances[1].stopped.Load())
	}
	if cm.loadedPlugins["alpha"] != instances[1] {
		t.Fatal("new generation not authoritative after reload")
	}
}

func TestConfigManagerFailedStagingRollsBackNewPluginsAndKeepsOldState(t *testing.T) {
	isolatePluginRegistry(t)

	stable := &configTestPlugin{name: "stable"}
	RegisterPlugin("stable", func() Plugin { return stable })
	cm := NewConfigManager()
	if err := cm.HotReload([]byte(`{"proxy_port":1080,"plugins":{"stable":{"v":1}}}`)); err != nil {
		t.Fatalf("initial reload: %v", err)
	}
	oldHash := cm.ActiveHash()

	started := &configTestPlugin{name: "a"}
	failed := &configTestPlugin{name: "b", startErr: errors.New("boom")}
	RegisterPlugin("a", func() Plugin { return started })
	RegisterPlugin("b", func() Plugin { return failed })

	err := cm.HotReload([]byte(`{
		"proxy_port":2080,
		"plugins":{"stable":{"v":1},"a":{"v":1},"b":{"v":1}}
	}`))
	if err == nil {
		t.Fatal("expected staged start failure")
	}
	if got := cm.ActiveHash(); got != oldHash {
		t.Fatalf("active hash changed after failed staging: got %s want %s", got, oldHash)
	}
	if cfg := cm.ActiveConfig(); cfg == nil || cfg.ProxyPort != 1080 {
		t.Fatalf("old config not preserved after failed staging: %#v", cfg)
	}
	if cm.loadedPlugins["stable"] != stable || len(cm.loadedPlugins) != 1 {
		t.Fatalf("old plugin state was not preserved: %#v", cm.loadedPlugins)
	}
	if stable.stopped.Load() != 0 {
		t.Fatalf("reused old plugin stopped during rollback: %d", stable.stopped.Load())
	}
	if started.stopped.Load() != 1 || failed.stopped.Load() != 1 {
		t.Fatalf("staged cleanup incomplete: a=%d b=%d", started.stopped.Load(), failed.stopped.Load())
	}
}

func TestConfigManagerRejectsUnknownFieldsAndTrailingJSON(t *testing.T) {
	isolatePluginRegistry(t)
	cm := NewConfigManager()

	for _, input := range []string{
		`{"proxy_port":1080,"surprise":true}`,
		`{"proxy_port":1080} {"dns_port":53}`,
	} {
		if err := cm.HotReload([]byte(input)); err == nil {
			t.Fatalf("expected strict decode failure for %s", input)
		}
	}
	if cm.ActiveConfig() != nil || cm.ActiveHash() != "" {
		t.Fatal("invalid config changed published state")
	}
}

func TestConfigManagerActiveConfigIsDeepCopy(t *testing.T) {
	isolatePluginRegistry(t)
	RegisterPlugin("alpha", func() Plugin { return &configTestPlugin{name: "alpha"} })
	cm := NewConfigManager()
	if err := cm.HotReload([]byte(`{"plugins":{"alpha":{"key":"original"}}}`)); err != nil {
		t.Fatalf("reload: %v", err)
	}

	copyCfg := cm.ActiveConfig()
	copyCfg.Plugins["alpha"][0] = 'x'
	delete(copyCfg.Plugins, "alpha")

	again := cm.ActiveConfig()
	if _, ok := again.Plugins["alpha"]; !ok {
		t.Fatal("caller mutation escaped into authoritative plugin map")
	}
	if string(again.Plugins["alpha"]) != `{"key":"original"}` {
		t.Fatalf("caller mutation escaped into authoritative raw config: %s", again.Plugins["alpha"])
	}
}

func TestConfigManagerReadersAreNotBlockedByPluginStart(t *testing.T) {
	isolatePluginRegistry(t)
	RegisterPlugin("stable", func() Plugin { return &configTestPlugin{name: "stable"} })
	cm := NewConfigManager()
	if err := cm.HotReload([]byte(`{"proxy_port":1080,"plugins":{"stable":{"v":1}}}`)); err != nil {
		t.Fatalf("initial reload: %v", err)
	}

	gate := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	RegisterPlugin("blocking", func() Plugin {
		return &configTestPlugin{name: "blocking", startGate: gate}
	})
	// Wrap the registered constructor so the test knows Start is about to block.
	pluginRegistryMu.Lock()
	base := pluginRegistry["blocking"]
	pluginRegistry["blocking"] = func() Plugin {
		p := base().(*configTestPlugin)
		p.startGate = func() <-chan struct{} {
			once.Do(func() { close(started) })
			return gate
		}()
		return p
	}
	pluginRegistryMu.Unlock()

	done := make(chan error, 1)
	go func() {
		done <- cm.HotReload([]byte(`{"proxy_port":2080,"plugins":{"stable":{"v":1},"blocking":{"v":1}}}`))
	}()
	<-started

	readDone := make(chan *DaemonConfig, 1)
	go func() { readDone <- cm.ActiveConfig() }()
	select {
	case cfg := <-readDone:
		if cfg == nil || cfg.ProxyPort != 1080 {
			t.Fatalf("reader observed unpublished state: %#v", cfg)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("ActiveConfig blocked behind plugin Start")
	}

	close(gate)
	if err := <-done; err != nil {
		t.Fatalf("reload after gate release: %v", err)
	}
}

func TestConfigManagerCleanupErrorReportsCommittedState(t *testing.T) {
	isolatePluginRegistry(t)
	var generation atomic.Int32
	var first *configTestPlugin
	RegisterPlugin("alpha", func() Plugin {
		p := &configTestPlugin{name: "alpha"}
		if generation.Add(1) == 1 {
			p.stopErr = errors.New("cannot retire")
			first = p
		}
		return p
	})

	cm := NewConfigManager()
	if err := cm.HotReload([]byte(`{"proxy_port":1080,"plugins":{"alpha":{"v":1}}}`)); err != nil {
		t.Fatalf("initial reload: %v", err)
	}
	err := cm.HotReload([]byte(`{"proxy_port":2080,"plugins":{"alpha":{"v":2}}}`))
	if !errors.Is(err, ErrConfigCleanup) {
		t.Fatalf("expected cleanup sentinel, got %v", err)
	}
	if cfg := cm.ActiveConfig(); cfg == nil || cfg.ProxyPort != 2080 {
		t.Fatalf("new config should remain committed after retirement error: %#v", cfg)
	}
	if first.stopped.Load() != 1 {
		t.Fatalf("old generation stop count=%d, want 1", first.stopped.Load())
	}
}

func TestConfigManagerHotReloadIfHashRejectsStaleWriter(t *testing.T) {
	isolatePluginRegistry(t)
	var created atomic.Int32
	RegisterPlugin("alpha", func() Plugin {
		created.Add(1)
		return &configTestPlugin{name: "alpha"}
	})

	cm := NewConfigManager()
	if err := cm.HotReload([]byte(`{"proxy_port":1080,"plugins":{"alpha":{"v":1}}}`)); err != nil {
		t.Fatalf("initial reload: %v", err)
	}
	staleHash := cm.ActiveHash()
	if err := cm.HotReload([]byte(`{"proxy_port":2080,"plugins":{"alpha":{"v":1}}}`)); err != nil {
		t.Fatalf("second reload: %v", err)
	}
	currentHash := cm.ActiveHash()

	err := cm.HotReloadIfHash([]byte(`{"proxy_port":3080,"plugins":{"alpha":{"v":2}}}`), staleHash)
	if !errors.Is(err, ErrConfigConflict) {
		t.Fatalf("stale writer error = %v, want ErrConfigConflict", err)
	}
	if got := cm.ActiveHash(); got != currentHash {
		t.Fatalf("stale writer changed active hash: got %s want %s", got, currentHash)
	}
	if got := created.Load(); got != 1 {
		t.Fatalf("stale writer constructed new plugin generation: constructors=%d", got)
	}
}

func TestConfigValidationBounds(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
	}{
		{name: "negative proxy", json: `{"proxy_port":-1}`},
		{name: "oversized dns", json: `{"dns_port":65536}`},
		{name: "bad log level", json: `{"log_level":"verbose"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cm := NewConfigManager()
			if err := cm.HotReload([]byte(tc.json)); err == nil {
				t.Fatalf("expected validation error for %s", tc.json)
			}
		})
	}
}

func TestRegisterPluginRejectsInvalidRegistration(t *testing.T) {
	isolatePluginRegistry(t)
	for _, tc := range []struct {
		name string
		ctor func() Plugin
	}{
		{name: "", ctor: func() Plugin { return &configTestPlugin{} }},
		{name: "alpha", ctor: nil},
	} {
		t.Run(fmt.Sprintf("name=%q", tc.name), func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("expected panic for invalid plugin registration")
				}
			}()
			RegisterPlugin(tc.name, tc.ctor)
		})
	}
}
