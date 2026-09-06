// Package system provides dynamic runtime configuration hot-reload for the LumiNet daemon.
//
// Converged from caddy-master (Apache-2.0) semantics rather than upstream packaging:
//   - semantic JSON change detection
//   - stage-before-commit reloads with rollback cleanup
//   - reuse of unchanged plugin instances
//   - short state-lock critical sections around an atomic config swap
//   - deterministic retirement of replaced/removed plugins after commit
package system

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
)

// DaemonConfig is the top-level LumiNet daemon runtime configuration.
// Changes are applied atomically via HotReload without restarting the process.
type DaemonConfig struct {
	// ProxyPort is the local SOCKS5/HTTP proxy listener port.
	ProxyPort int `json:"proxy_port,omitempty"`
	// DNSPort is the local DNS resolver port.
	DNSPort int `json:"dns_port,omitempty"`
	// TunEnabled activates the virtual TUN interface.
	TunEnabled bool `json:"tun_enabled,omitempty"`
	// LogLevel controls the log verbosity ("debug", "info", "warn", "error").
	LogLevel string `json:"log_level,omitempty"`
	// Plugins is a map of plugin names to their raw JSON configurations.
	Plugins map[string]json.RawMessage `json:"plugins,omitempty"`
}

// Plugin is the interface all hot-reloadable daemon plugins must implement.
// Lifecycle: Provision() -> Start() -> Stop(). Stop must be idempotent and is
// also used to roll back a plugin whose Provision or Start only partially
// succeeded.
type Plugin interface {
	// Name returns the plugin's registration key.
	Name() string
	// Provision configures the plugin from its raw JSON configuration.
	Provision(rawCfg json.RawMessage) error
	// Start activates the plugin. Called after Provision succeeds.
	Start() error
	// Stop deactivates the plugin. Must be idempotent.
	Stop() error
}

var (
	pluginRegistryMu sync.RWMutex
	pluginRegistry   = map[string]func() Plugin{}
)

// RegisterPlugin registers or replaces a plugin constructor. Registration is
// process-global, so lookup and mutation are synchronized with hot reloads.
func RegisterPlugin(name string, ctor func() Plugin) {
	if name == "" {
		panic("system: cannot register plugin with empty name")
	}
	if ctor == nil {
		panic(fmt.Sprintf("system: cannot register nil constructor for plugin %q", name))
	}
	pluginRegistryMu.Lock()
	pluginRegistry[name] = ctor
	pluginRegistryMu.Unlock()
}

// ConfigManager manages the active daemon config with hot-reload support.
// reloadMu serializes lifecycle transitions while mu protects only published
// state. Plugin lifecycle methods are never called while mu is held.
type ConfigManager struct {
	reloadMu sync.Mutex
	mu       sync.RWMutex

	active        *DaemonConfig
	activeHash    string
	loadedPlugins map[string]Plugin
}

// NewConfigManager creates a ConfigManager with an empty initial config.
func NewConfigManager() *ConfigManager {
	return &ConfigManager{loadedPlugins: make(map[string]Plugin)}
}

// HotReload applies a new JSON configuration transactionally.
//
// The new configuration is decoded strictly and normalized before comparison.
// Unchanged plugin instances are reused. Added or changed plugins are fully
// provisioned and started before the new state is published. If staging fails,
// every newly-created plugin is stopped in reverse order and the old published
// state remains authoritative. Once all staging succeeds, the config is
// atomically swapped, then replaced/removed old plugins are retired outside the
// state lock.
func (cm *ConfigManager) HotReload(cfgJSON []byte) error {
	return cm.hotReload(cfgJSON, "")
}

// HotReloadIfHash is the optimistic-concurrency form of HotReload. When
// expectedHash is non-empty, the reload is rejected unless it still matches
// the currently published canonical config hash. This prevents a stale
// operator/config editor from overwriting a newer generation.
func (cm *ConfigManager) HotReloadIfHash(cfgJSON []byte, expectedHash string) error {
	return cm.hotReload(cfgJSON, expectedHash)
}

func (cm *ConfigManager) hotReload(cfgJSON []byte, expectedHash string) error {
	newCfg, canonical, err := parseDaemonConfig(cfgJSON)
	if err != nil {
		return err
	}
	newHash := configHash(canonical)

	cm.reloadMu.Lock()
	defer cm.reloadMu.Unlock()

	oldCfg, oldHash, oldPlugins := cm.snapshotState()
	if expectedHash != "" && expectedHash != oldHash {
		return fmt.Errorf("config changed since caller snapshot (expected=%s actual=%s): %w", expectedHash, oldHash, ErrConfigConflict)
	}
	if newHash == oldHash {
		return fmt.Errorf("config unchanged (hash=%s): %w", newHash, ErrConfigUnchanged)
	}

	constructors := snapshotPluginRegistry()
	newPlugins := make(map[string]Plugin, len(newCfg.Plugins))
	staged := make([]namedPlugin, 0, len(newCfg.Plugins))

	for _, name := range sortedPluginNames(newCfg.Plugins) {
		rawPlugin := newCfg.Plugins[name]

		if oldCfg != nil && pluginConfigEqual(oldCfg.Plugins[name], rawPlugin) {
			if oldPlugin, ok := oldPlugins[name]; ok {
				newPlugins[name] = oldPlugin
				continue
			}
		}

		ctor, ok := constructors[name]
		if !ok {
			return cleanupStagedError(staged, fmt.Errorf("unknown plugin %q: not registered", name))
		}
		p := ctor()
		if p == nil {
			return cleanupStagedError(staged, fmt.Errorf("plugin %q constructor returned nil", name))
		}

		// Track the instance before Provision so partial provisioning can be
		// compensated through the idempotent Stop contract.
		staged = append(staged, namedPlugin{name: name, plugin: p})
		if err := p.Provision(cloneRawMessage(rawPlugin)); err != nil {
			return cleanupStagedError(staged, fmt.Errorf("plugin %q provision failed: %w", name, err))
		}
		if err := p.Start(); err != nil {
			return cleanupStagedError(staged, fmt.Errorf("plugin %q start failed: %w", name, err))
		}
		newPlugins[name] = p
	}

	cm.mu.Lock()
	cm.active = deepCopyDaemonConfig(newCfg)
	cm.activeHash = newHash
	cm.loadedPlugins = newPlugins
	cm.mu.Unlock()

	retired := pluginsToRetire(oldPlugins, newPlugins)
	if cleanupErr := stopNamedPlugins(retired); cleanupErr != nil {
		return fmt.Errorf("config reload committed (hash=%s), but retiring old plugins failed: %w", newHash, errors.Join(ErrConfigCleanup, cleanupErr))
	}
	return nil
}

// Stop terminates all loaded plugins cleanly. It preserves the historical
// no-return-value API; callers that need the cleanup result can use
// StopWithError.
func (cm *ConfigManager) Stop() {
	_ = cm.StopWithError()
}

// StopWithError atomically clears published configuration state, then stops
// the formerly active plugins outside the state lock.
func (cm *ConfigManager) StopWithError() error {
	cm.reloadMu.Lock()
	defer cm.reloadMu.Unlock()

	cm.mu.Lock()
	oldPlugins := clonePluginMap(cm.loadedPlugins)
	cm.active = nil
	cm.activeHash = ""
	cm.loadedPlugins = make(map[string]Plugin)
	cm.mu.Unlock()

	return stopNamedPlugins(namedPluginsFromMap(oldPlugins))
}

// ActiveConfig returns a deep copy of the currently active daemon config.
// Callers cannot mutate the manager's authoritative plugin map or raw JSON.
func (cm *ConfigManager) ActiveConfig() *DaemonConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return deepCopyDaemonConfig(cm.active)
}

// ActiveHash returns the SHA-256 hash of the canonical active configuration.
func (cm *ConfigManager) ActiveHash() string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.activeHash
}

var (
	// ErrConfigUnchanged is returned when the new config is semantically
	// identical to the current one.
	ErrConfigUnchanged = errors.New("config unchanged")
	// ErrConfigCleanup identifies a reload that committed successfully but
	// could not completely retire the previous generation.
	ErrConfigCleanup = errors.New("config cleanup incomplete")
	// ErrConfigConflict identifies an optimistic-concurrency precondition that
	// no longer matches the active configuration generation.
	ErrConfigConflict = errors.New("config generation conflict")
)

type namedPlugin struct {
	name   string
	plugin Plugin
}

func (cm *ConfigManager) snapshotState() (*DaemonConfig, string, map[string]Plugin) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return deepCopyDaemonConfig(cm.active), cm.activeHash, clonePluginMap(cm.loadedPlugins)
}

func snapshotPluginRegistry() map[string]func() Plugin {
	pluginRegistryMu.RLock()
	defer pluginRegistryMu.RUnlock()
	out := make(map[string]func() Plugin, len(pluginRegistry))
	for name, ctor := range pluginRegistry {
		out[name] = ctor
	}
	return out
}

func parseDaemonConfig(data []byte) (*DaemonConfig, []byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg DaemonConfig
	if err := dec.Decode(&cfg); err != nil {
		return nil, nil, fmt.Errorf("config parse error: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, nil, fmt.Errorf("config parse error: trailing JSON value")
		}
		return nil, nil, fmt.Errorf("config parse error: trailing data: %w", err)
	}
	if err := validateDaemonConfig(&cfg); err != nil {
		return nil, nil, err
	}

	if cfg.Plugins == nil {
		cfg.Plugins = make(map[string]json.RawMessage)
	}
	for name, raw := range cfg.Plugins {
		canonical, err := canonicalJSON(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("plugin %q config: %w", name, err)
		}
		cfg.Plugins[name] = canonical
	}

	canonical, err := json.Marshal(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("config canonicalization failed: %w", err)
	}
	return &cfg, canonical, nil
}

func validateDaemonConfig(cfg *DaemonConfig) error {
	if cfg.ProxyPort < 0 || cfg.ProxyPort > 65535 {
		return fmt.Errorf("config validation error: proxy_port must be between 0 and 65535")
	}
	if cfg.DNSPort < 0 || cfg.DNSPort > 65535 {
		return fmt.Errorf("config validation error: dns_port must be between 0 and 65535")
	}
	switch cfg.LogLevel {
	case "", "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config validation error: unsupported log_level %q", cfg.LogLevel)
	}
	for name := range cfg.Plugins {
		if name == "" {
			return fmt.Errorf("config validation error: plugin name cannot be empty")
		}
	}
	return nil
}

func canonicalJSON(raw []byte) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("invalid JSON: trailing value")
		}
		return nil, fmt.Errorf("invalid JSON: trailing data: %w", err)
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("canonicalize JSON: %w", err)
	}
	return json.RawMessage(canonical), nil
}

func sortedPluginNames(plugins map[string]json.RawMessage) []string {
	names := make([]string, 0, len(plugins))
	for name := range plugins {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func pluginConfigEqual(a, b json.RawMessage) bool {
	return len(a) > 0 && bytes.Equal(a, b)
}

func cleanupStagedError(staged []namedPlugin, cause error) error {
	if cleanupErr := stopNamedPluginsReverse(staged); cleanupErr != nil {
		return errors.Join(cause, fmt.Errorf("rollback staged plugins: %w", cleanupErr))
	}
	return cause
}

func pluginsToRetire(oldPlugins, newPlugins map[string]Plugin) []namedPlugin {
	retired := make([]namedPlugin, 0, len(oldPlugins))
	for name, oldPlugin := range oldPlugins {
		if current, ok := newPlugins[name]; ok && current == oldPlugin {
			continue
		}
		retired = append(retired, namedPlugin{name: name, plugin: oldPlugin})
	}
	sort.Slice(retired, func(i, j int) bool { return retired[i].name < retired[j].name })
	return retired
}

func namedPluginsFromMap(plugins map[string]Plugin) []namedPlugin {
	items := make([]namedPlugin, 0, len(plugins))
	for name, plugin := range plugins {
		items = append(items, namedPlugin{name: name, plugin: plugin})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].name < items[j].name })
	return items
}

func stopNamedPluginsReverse(items []namedPlugin) error {
	var errs []error
	for i := len(items) - 1; i >= 0; i-- {
		item := items[i]
		if item.plugin == nil {
			continue
		}
		if err := item.plugin.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("plugin %q stop: %w", item.name, err))
		}
	}
	return errors.Join(errs...)
}

func stopNamedPlugins(items []namedPlugin) error {
	var errs []error
	for _, item := range items {
		if item.plugin == nil {
			continue
		}
		if err := item.plugin.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("plugin %q stop: %w", item.name, err))
		}
	}
	return errors.Join(errs...)
}

func deepCopyDaemonConfig(cfg *DaemonConfig) *DaemonConfig {
	if cfg == nil {
		return nil
	}
	copyCfg := *cfg
	if cfg.Plugins != nil {
		copyCfg.Plugins = make(map[string]json.RawMessage, len(cfg.Plugins))
		for name, raw := range cfg.Plugins {
			copyCfg.Plugins[name] = cloneRawMessage(raw)
		}
	}
	return &copyCfg
}

func cloneRawMessage(raw json.RawMessage) json.RawMessage {
	if raw == nil {
		return nil
	}
	return append(json.RawMessage(nil), raw...)
}

func clonePluginMap(plugins map[string]Plugin) map[string]Plugin {
	out := make(map[string]Plugin, len(plugins))
	for name, plugin := range plugins {
		out[name] = plugin
	}
	return out
}

// configHash returns a hex-encoded SHA-256 hash of canonical JSON bytes.
func configHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
