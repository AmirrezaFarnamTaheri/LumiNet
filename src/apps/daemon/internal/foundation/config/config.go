// Package config handles the configuration loading, saving, and validation for the server.
package config

import (
	"context"
	stdsha256 "crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/maybeknott/luminet/internal/foundation/crypto"
	"github.com/maybeknott/luminet/internal/foundation/secrets"
)

// ErrConfigNotFound is returned when the configuration file does not exist.
var ErrConfigNotFound = errors.New("configuration file not found")

// ErrRevisionConflict is returned when a caller attempts to persist a stale
// configuration snapshot. Callers may reload and deliberately reapply their
// change, but the manager never silently overwrites a newer authoritative
// configuration revision.
var ErrRevisionConflict = errors.New("configuration revision conflict")

const (
	// DefaultMutationAttempts is the bounded retry budget for server-owned
	// read-modify-write intents. Explicit client preconditions never use this
	// budget: a stale If-Match/body revision must fail rather than be replayed.
	DefaultMutationAttempts = 3
	MaxMutationAttempts     = 8
)

// MutationResult reports the durable outcome of an intent-based configuration
// mutation. Attempts is deliberately observable so callers can distinguish an
// uncontended write from a write that had to reconcile a concurrent revision.
type MutationResult struct {
	Revision uint64
	Attempts int
}

// MutationStats exposes monotonic counters for the local optimistic-concurrency
// authority. These counters describe only Config.Manager mutations; remote or
// externally side-effecting retries remain owned by foundation/remoteaction.
type MutationStats struct {
	Calls            uint64 `json:"calls"`
	Commits          uint64 `json:"commits"`
	Conflicts        uint64 `json:"conflicts"`
	AutomaticRetries uint64 `json:"automatic_retries"`
	ExhaustedRetries uint64 `json:"exhausted_retries"`
}

// MutationOptions controls optimistic-concurrency behavior for Mutate. When
// ExpectedRevision is non-nil, Mutate performs exactly one compare-and-swap and
// never replays the mutation. Without an explicit revision, MaxAttempts bounds
// automatic replay against fresh authoritative snapshots.
type MutationOptions struct {
	ExpectedRevision *uint64
	MaxAttempts      int
}

// Config represents the application configuration structure.
type Config struct {
	// ConfigRevision is the durable generation of the authoritative settings
	// document. It is intentionally persisted so optimistic-concurrency tokens
	// cannot suffer an ABA reset when the daemon restarts.
	ConfigRevision uint64 `json:"_revision,omitempty"`

	ServerAddr  string            `json:"server_addr"`
	LogLevel    string            `json:"log_level"`
	DBPath      string            `json:"db_path"`
	DDNS        DDNSConfig        `json:"ddns"`
	SystemProxy ProxyConfig       `json:"system_proxy"`
	ProxyNodes  []ProxyNodeConfig `json:"proxy_nodes"`
	PluginsDir  string            `json:"plugins_dir"`

	// ponytail: simplify settings storage by keeping scanner engine values at the root config structure
	DefaultTimeoutMs          int                    `json:"default_timeout_ms"`
	MaxConcurrency            int                    `json:"max_concurrency"`
	DebugLogs                 bool                   `json:"debug_logs"`
	DNSResolution             bool                   `json:"dns_resolution"`
	DecoyTraffic              DecoyTrafficConfig     `json:"decoy_traffic"`
	CaptchaSolver             CaptchaSolverConfig    `json:"captcha_solver"`
	UpgenObfuscation          UpgenObfuscationConfig `json:"upgen_obfuscation"`
	MihomoRules               MihomoRulesOptions     `json:"mihomo_rules"`
	Steganography             SteganographyConfig    `json:"steganography"`
	HostsOverride             bool                   `json:"hosts_override"`
	NetworkHealthAuditEnabled bool                   `json:"network_health_audit_enabled"`
	UpdateAdmission           UpdateAdmissionConfig  `json:"update_admission"`

	// RandmapEgress configures source-address randomisation on egress
	// traffic via lumicore's randmap engines. Nil/empty = disabled.
	RandmapEgress *RandmapEgressConfig `json:"randmap_egress,omitempty"`
}

// UpdateAdmissionConfig contains public trust roots only. These keys may admit
// a signed update manifest for planning, but they never authorize download or
// installation by themselves.
type UpdateAdmissionConfig struct {
	TrustedKeys map[string]string `json:"trusted_keys,omitempty"`
}

// MihomoRulesOptions defines options for customizing Clash config rules generation.
type MihomoRulesOptions struct {
	BypassIran        bool `json:"bypass_iran"`
	BypassChina       bool `json:"bypass_china"`
	BypassRussia      bool `json:"bypass_russia"`
	BypassOpenAI      bool `json:"bypass_openai"`
	BypassShaparak    bool `json:"bypass_shaparak"`
	BypassGoogleAI    bool `json:"bypass_google_ai"`
	BypassMicrosoft   bool `json:"bypass_microsoft"`
	BypassOracle      bool `json:"bypass_oracle"`
	BypassDocker      bool `json:"bypass_docker"`
	BypassAdobe       bool `json:"bypass_adobe"`
	BypassEpicGames   bool `json:"bypass_epic_games"`
	BypassIntel       bool `json:"bypass_intel"`
	BypassAMD         bool `json:"bypass_amd"`
	BypassNvidia      bool `json:"bypass_nvidia"`
	BypassAsus        bool `json:"bypass_asus"`
	BypassHP          bool `json:"bypass_hp"`
	BypassLenovo      bool `json:"bypass_lenovo"`
	BypassYouTube     bool `json:"bypass_youtube"`
	BlockMalware      bool `json:"block_malware"`
	BlockPhishing     bool `json:"block_phishing"`
	BlockCryptominers bool `json:"block_cryptominers"`
	BlockAds          bool `json:"block_ads"`
	BlockPorn         bool `json:"block_porn"`
}

// SteganographyConfig represents settings for VoIP/WebRTC and Intranet steganographic camouflage.
type SteganographyConfig struct {
	Enabled        bool   `json:"enabled"`
	Mode           string `json:"mode"`
	DecoyImagePath string `json:"decoy_image_path"`
	WebRTCSDPSpoof bool   `json:"webrtc_sdp_spoof"`
}

// UpgenObfuscationConfig represents settings for the context-free grammar and QUIC queue exhaustion obfuscation.
type UpgenObfuscationConfig struct {
	Enabled            bool   `json:"enabled"`
	SeedHex            string `json:"seed_hex"`
	EntropyMatch       bool   `json:"entropy_match"`
	QUICExhaustionRate int    `json:"quic_exhaustion_rate"`
}

// ProxyNodeConfig represents a registered proxy server in the directory.
type ProxyNodeConfig struct {
	ID       string `json:"id"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Type     string `json:"type"`
	Auth     bool   `json:"auth"`
	Username string `json:"username,omitempty"`
	// Password exists only in the in-memory runtime model. Save persists its
	// provider-bound PasswordRef instead of serializing this field.
	Password    string            `json:"password,omitempty"`
	PasswordRef secrets.SecretRef `json:"password_ref,omitempty"`
	Notes       string            `json:"notes"`
}

// DDNSConfig represents the DDNS specific configuration parameters.
type DDNSConfig struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"`
	// Token is retained in memory for the DDNS client. Persisted configuration
	// uses TokenRef; Token is only read for one-time legacy migration.
	Token    string            `json:"token,omitempty"`
	TokenRef secrets.SecretRef `json:"token_ref,omitempty"`
	Domain   string            `json:"domain"`
	Interval int               `json:"interval_minutes"`
}

// ProxyConfig represents the system proxy specific configuration parameters.
type ProxyConfig struct {
	Enabled bool   `json:"enabled"`
	Address string `json:"address"`
	Bypass  string `json:"bypass"`
}

// DecoyTrafficConfig represents settings for the background decoy traffic generator.
type DecoyTrafficConfig struct {
	Enabled         bool     `json:"enabled"`
	Targets         []string `json:"targets"`
	VolumePerMinute int      `json:"volume_per_minute"`
}

// CaptchaSolverConfig represents settings for the CAPTCHA/WAF solver integration.
type CaptchaSolverConfig struct {
	Enabled     bool              `json:"enabled"`
	APIKey      string            `json:"api_key,omitempty"`
	APIKeyRef   secrets.SecretRef `json:"api_key_ref,omitempty"`
	EndpointURL string            `json:"endpoint_url"`
}

// Manager orchestrates loading, saving, and dynamically updating configuration.
type Manager struct {
	configPath  string
	mu          sync.RWMutex
	current     *Config
	revision    uint64
	secretStore secrets.Store
	fileHash    [stdsha256.Size]byte
	fileHashSet bool

	mutationCalls            atomic.Uint64
	mutationCommits          atomic.Uint64
	mutationConflicts        atomic.Uint64
	mutationAutomaticRetries atomic.Uint64
	mutationExhaustedRetries atomic.Uint64
}

// NewManager creates a new config Manager with the specified path.
func NewManager(configPath string) *Manager {
	store, _ := secrets.OpenNativeStore()
	return NewManagerWithSecretStore(configPath, store)
}

// NewManagerWithSecretStore is the explicit construction path for tests and
// controlled embedding. Production callers must provide a native store; no
// filesystem fallback is selected here.
func NewManagerWithSecretStore(configPath string, secretStore secrets.Store) *Manager {
	return &Manager{
		configPath:  configPath,
		current:     DefaultConfig(),
		secretStore: secretStore,
	}
}

// EncryptSensitiveFields encrypts sensitive fields in the configuration.
func (c *Config) EncryptSensitiveFields() error {
	// Encrypt DDNS Token
	if c.DDNS.Token != "" {
		enc, err := crypto.Encrypt([]byte(c.DDNS.Token))
		if err != nil {
			return err
		}
		c.DDNS.Token = base64.StdEncoding.EncodeToString(enc)
	}

	// Encrypt Proxy Node Passwords
	for i := range c.ProxyNodes {
		if c.ProxyNodes[i].Password != "" {
			enc, err := crypto.Encrypt([]byte(c.ProxyNodes[i].Password))
			if err != nil {
				return err
			}
			c.ProxyNodes[i].Password = base64.StdEncoding.EncodeToString(enc)
		}
	}

	// Encrypt Captcha Solver API Key
	if c.CaptchaSolver.APIKey != "" {
		enc, err := crypto.Encrypt([]byte(c.CaptchaSolver.APIKey))
		if err != nil {
			return err
		}
		c.CaptchaSolver.APIKey = base64.StdEncoding.EncodeToString(enc)
	}

	// Encrypt Upgen Obfuscation SeedHex
	if c.UpgenObfuscation.SeedHex != "" {
		enc, err := crypto.Encrypt([]byte(c.UpgenObfuscation.SeedHex))
		if err != nil {
			return err
		}
		c.UpgenObfuscation.SeedHex = base64.StdEncoding.EncodeToString(enc)
	}
	return nil
}

// DecryptSensitiveFields decrypts sensitive fields in the configuration.
func (c *Config) DecryptSensitiveFields() error {
	// Decrypt DDNS Token
	if c.DDNS.Token != "" {
		decoded, err := base64.StdEncoding.DecodeString(c.DDNS.Token)
		if err != nil {
			return err
		}
		dec, err := crypto.Decrypt(decoded)
		if err != nil {
			return err
		}
		c.DDNS.Token = string(dec)
	}

	// Decrypt Proxy Node Passwords
	for i := range c.ProxyNodes {
		if c.ProxyNodes[i].Password != "" {
			decoded, err := base64.StdEncoding.DecodeString(c.ProxyNodes[i].Password)
			if err != nil {
				return err
			}
			dec, err := crypto.Decrypt(decoded)
			if err != nil {
				return err
			}
			c.ProxyNodes[i].Password = string(dec)
		}
	}

	// Decrypt Captcha Solver API Key
	if c.CaptchaSolver.APIKey != "" {
		decoded, err := base64.StdEncoding.DecodeString(c.CaptchaSolver.APIKey)
		if err != nil {
			return err
		}
		dec, err := crypto.Decrypt(decoded)
		if err != nil {
			return err
		}
		c.CaptchaSolver.APIKey = string(dec)
	}

	// Decrypt Upgen Obfuscation SeedHex
	if c.UpgenObfuscation.SeedHex != "" {
		decoded, err := base64.StdEncoding.DecodeString(c.UpgenObfuscation.SeedHex)
		if err == nil {
			dec, err := crypto.Decrypt(decoded)
			if err == nil {
				c.UpgenObfuscation.SeedHex = string(dec)
			}
		}
	}
	return nil
}

// Load loads the configuration from the file. If file does not exist, defaults are used.
func (m *Manager) Load() (*Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.configPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// If file does not exist, populate with defaults and write it atomically
			m.current = DefaultConfig()
			saveErr := m.saveUnlocked(m.current)
			if saveErr != nil {
				return nil, saveErr
			}
			return m.deepCopy(m.current), nil
		}
		return nil, err
	}

	persistedHash := stdsha256.Sum256(data)
	samePersistedBytes := m.fileHashSet && m.fileHash == persistedHash

	// Merge config on top of default values to prevent zero-value wipes. A
	// structurally corrupt active file is moved aside before returning the
	// error. This preserves the exact damaged bytes for operator recovery while
	// ensuring the next startup cannot accidentally overwrite that evidence.
	cfg := *DefaultConfig()
	if err := json.Unmarshal(data, &cfg); err != nil {
		quarantined, quarantineErr := quarantineCorruptConfig(m.configPath)
		if quarantineErr != nil {
			return nil, fmt.Errorf("parse configuration: %w; quarantine failed: %v", err, quarantineErr)
		}
		return nil, fmt.Errorf("parse configuration: %w; quarantined damaged file at %s", err, quarantined)
	}

	if err := cfg.DecryptSensitiveFields(); err != nil {
		return nil, err
	}
	if err := m.hydrateReferencedSecrets(&cfg); err != nil {
		return nil, err
	}

	diskRevision := cfg.ConfigRevision
	initialLoad := m.revision == 0
	needsGenerationCommit := false
	switch {
	case initialLoad && diskRevision > 0:
		// Restart: resume the durable generation exactly.
		m.revision = diskRevision
	case initialLoad:
		// Legacy settings have no durable generation. Establish one atomically.
		needsGenerationCommit = true
	case diskRevision > m.revision:
		// An external generation-aware writer advanced the file. Accept its
		// monotonic generation and preserve it.
		m.revision = diskRevision
	case diskRevision == m.revision && samePersistedBytes:
		// The watcher may observe our own atomic rename or an operator may only
		// touch the file. Byte-identical authoritative content is already this
		// generation; rewriting it would create a self-triggering revision loop.
	case diskRevision <= m.revision:
		// The file bytes genuinely changed while reusing or rolling back an old
		// generation. Commit a fresh generation to prevent ABA/stale-writer reuse.
		needsGenerationCommit = true
	}

	// Legacy encrypted values and generation-less/stale-generation external
	// edits are migrated atomically. A native-store outage fails closed and
	// leaves the original file untouched rather than persisting a downgraded
	// representation.
	if cfg.hasInlineSecrets() || needsGenerationCommit {
		if err := m.saveUnlocked(&cfg); err != nil {
			return nil, fmt.Errorf("migrate configuration authority: %w", err)
		}
		return m.deepCopy(m.current), nil
	}

	cfg.ConfigRevision = m.revision
	m.current = m.deepCopy(&cfg)
	m.fileHash = persistedHash
	m.fileHashSet = true
	return m.deepCopy(m.current), nil
}

// SaveIfRevision atomically persists cfg only when expectedRevision still
// identifies the manager's current snapshot. It is the mutation primitive for
// read-modify-write callers that must not lose concurrent updates.
func (m *Manager) SaveIfRevision(cfg *Config, expectedRevision uint64) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revision != expectedRevision {
		return m.revision, fmt.Errorf("%w: expected %d, current %d", ErrRevisionConflict, expectedRevision, m.revision)
	}
	if err := m.saveUnlocked(cfg); err != nil {
		return m.revision, err
	}
	return m.revision, nil
}

// MutationStats returns a point-in-time snapshot of local configuration mutation
// telemetry. It is safe to call concurrently with Mutate.
func (m *Manager) MutationStats() MutationStats {
	if m == nil {
		return MutationStats{}
	}
	return MutationStats{
		Calls:            m.mutationCalls.Load(),
		Commits:          m.mutationCommits.Load(),
		Conflicts:        m.mutationConflicts.Load(),
		AutomaticRetries: m.mutationAutomaticRetries.Load(),
		ExhaustedRetries: m.mutationExhaustedRetries.Load(),
	}
}

// Mutate applies a side-effect-free configuration intent against an owned
// snapshot and commits it with optimistic concurrency. For server-owned
// mutations (no ExpectedRevision), a revision conflict reloads authority and
// replays the intent up to a strict bounded budget. This preserves concurrent
// unrelated edits without weakening explicit client preconditions.
//
// mutate MUST only modify the supplied Config and return an error. It must not
// perform external side effects because it can be invoked more than once.
func (m *Manager) Mutate(options MutationOptions, mutate func(*Config) error) (MutationResult, error) {
	if m == nil {
		return MutationResult{}, errors.New("configuration manager is required")
	}
	m.mutationCalls.Add(1)
	if mutate == nil {
		return MutationResult{Revision: m.Revision()}, errors.New("configuration mutation callback is required")
	}

	maxAttempts := options.MaxAttempts
	if options.ExpectedRevision != nil {
		maxAttempts = 1
	} else {
		if maxAttempts <= 0 {
			maxAttempts = DefaultMutationAttempts
		}
		if maxAttempts > MaxMutationAttempts {
			maxAttempts = MaxMutationAttempts
		}
	}

	var result MutationResult
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		cfg, revision := m.GetWithRevision()
		if options.ExpectedRevision != nil {
			revision = *options.ExpectedRevision
			if current := m.Revision(); current != revision {
				m.mutationConflicts.Add(1)
				return MutationResult{Revision: current, Attempts: attempt}, fmt.Errorf("%w: expected %d, current %d", ErrRevisionConflict, revision, current)
			}
		}

		if err := mutate(cfg); err != nil {
			return MutationResult{Revision: m.Revision(), Attempts: attempt}, err
		}

		newRevision, err := m.SaveIfRevision(cfg, revision)
		result = MutationResult{Revision: newRevision, Attempts: attempt}
		if err == nil {
			m.mutationCommits.Add(1)
			return result, nil
		}
		if !errors.Is(err, ErrRevisionConflict) {
			return result, err
		}
		m.mutationConflicts.Add(1)
		if options.ExpectedRevision != nil {
			return result, err
		}
		if attempt == maxAttempts {
			m.mutationExhaustedRetries.Add(1)
			return result, err
		}
		m.mutationAutomaticRetries.Add(1)
	}

	return result, fmt.Errorf("%w: mutation retry budget exhausted", ErrRevisionConflict)
}

// saveUnlocked persists the configuration to the config file path.
// The caller MUST hold the Manager's write lock.
func (m *Manager) saveUnlocked(cfg *Config) error {
	if cfg == nil {
		return errors.New("configuration is required")
	}
	// Deep clone to avoid modifying the reference being saved
	cfgCopy := m.deepCopy(cfg)

	stagedRefs, err := m.persistSecrets(cfgCopy)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			m.deleteSecretRefsBestEffort(stagedRefs)
		}
	}()

	// The generation is part of the durable document. Ignore any caller-supplied
	// generation and advance only from the manager's authoritative value.
	nextRevision := m.revision + 1
	if nextRevision == 0 {
		return errors.New("configuration revision exhausted")
	}
	cfgCopy.ConfigRevision = nextRevision

	// Ensure parent directory exists
	dir := filepath.Dir(m.configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfgCopy, "", "  ")
	if err != nil {
		return err
	}

	if err := writeAtomicPrivateFile(m.configPath, data); err != nil {
		return err
	}
	m.fileHash = stdsha256.Sum256(data)
	m.fileHashSet = true
	committed = true

	// The config file is now authoritative. Retire secret references that were
	// reachable from the previous snapshot but are no longer reachable from the
	// committed one. Cleanup is deliberately best-effort after commit: a failed
	// delete can leave an inert orphan, but can never make the newly committed
	// configuration unavailable.
	m.retireSupersededSecretRefs(m.current, cfgCopy)

	// Publish an owned runtime snapshot only after durable persistence succeeds.
	// Secret references generated during persistence belong to the authoritative
	// runtime state, while secret values remain hydrated in memory for their
	// owning clients. Never retain the caller's mutable pointer.
	published := m.deepCopy(cfg)
	published.DDNS.TokenRef = cfgCopy.DDNS.TokenRef
	published.CaptchaSolver.APIKeyRef = cfgCopy.CaptchaSolver.APIKeyRef
	for i := range published.ProxyNodes {
		if i < len(cfgCopy.ProxyNodes) {
			published.ProxyNodes[i].PasswordRef = cfgCopy.ProxyNodes[i].PasswordRef
		}
	}
	published.ConfigRevision = nextRevision
	m.current = published
	m.revision = nextRevision
	return nil
}

func (c *Config) hasInlineSecrets() bool {
	// Only fields that migrate to native SecretRef storage belong here. The
	// Upgen seed intentionally remains encrypted inline for now; counting it as
	// a migration candidate would rewrite an otherwise unchanged config on every
	// load/restart.
	if c.DDNS.Token != "" || c.CaptchaSolver.APIKey != "" {
		return true
	}
	for _, node := range c.ProxyNodes {
		if node.Password != "" {
			return true
		}
	}
	return false
}

func (m *Manager) persistSecrets(cfg *Config) ([]string, error) {
	currentSecrets := secretValueIndex(m.current)
	staged := make([]string, 0, 2+len(cfg.ProxyNodes))
	stage := func(ref *secrets.SecretRef, value *string, namespace string) error {
		newRef, err := m.persistSecretCopyOnWrite(*ref, *value, namespace, currentSecrets)
		if err != nil {
			return err
		}
		if newRef.Ref != "" && newRef.Ref != ref.Ref {
			staged = append(staged, newRef.Ref)
		}
		*ref = newRef
		*value = ""
		return nil
	}

	if err := stage(&cfg.DDNS.TokenRef, &cfg.DDNS.Token, "ddns"); err != nil {
		m.deleteSecretRefsBestEffort(staged)
		return nil, err
	}
	if err := stage(&cfg.CaptchaSolver.APIKeyRef, &cfg.CaptchaSolver.APIKey, "captcha"); err != nil {
		m.deleteSecretRefsBestEffort(staged)
		return nil, err
	}
	for i := range cfg.ProxyNodes {
		if err := stage(&cfg.ProxyNodes[i].PasswordRef, &cfg.ProxyNodes[i].Password, "proxy"); err != nil {
			m.deleteSecretRefsBestEffort(staged)
			return nil, err
		}
	}
	// The seed keeps its previous encrypted representation until its owning
	// obfuscation unit is migrated; never serialize it as plaintext here.
	if err := cfg.EncryptSensitiveFields(); err != nil {
		m.deleteSecretRefsBestEffort(staged)
		return nil, err
	}
	return staged, nil
}

// persistSecretCopyOnWrite prepares one referenced secret without ever
// overwriting a secret that is reachable from the currently committed config.
// If the caller's value/ref pair exactly matches the authoritative snapshot,
// the existing ref is retained without another store write. A changed value
// receives a fresh ref; that staged ref can then be rolled back safely if the
// subsequent config-file commit fails.
func (m *Manager) persistSecretCopyOnWrite(ref secrets.SecretRef, value, namespace string, current map[string]string) (secrets.SecretRef, error) {
	if value == "" {
		if ref.Ref == "" {
			return ref, nil
		}
		if err := secrets.ValidateStoreRef(m.secretStore, ref, true); err != nil {
			return secrets.SecretRef{}, err
		}
		return ref, nil
	}
	if m.secretStore == nil {
		return secrets.SecretRef{}, fmt.Errorf("%w: %s secret requires a native provider", secrets.ErrNativeStoreUnavailable, namespace)
	}
	provider, ok := m.secretStore.(secrets.ProviderStore)
	if !ok {
		return secrets.SecretRef{}, errors.New("configured secret store has no provider identity")
	}
	if ref.Ref != "" {
		if err := secrets.ValidateStoreRef(m.secretStore, ref, true); err != nil {
			return secrets.SecretRef{}, err
		}
		if committedValue, ok := current[ref.Ref]; ok && committedValue == value {
			return ref, nil
		}
	}

	newRef := secrets.SecretRef{Provider: provider.ProviderName(), Ref: "config/" + namespace + "/" + uuid.NewString()}
	if err := secrets.ValidateStoreRef(m.secretStore, newRef, true); err != nil {
		return secrets.SecretRef{}, err
	}
	if err := m.secretStore.Put(context.Background(), newRef.Ref, []byte(value)); err != nil {
		return secrets.SecretRef{}, err
	}
	return newRef, nil
}

func secretValueIndex(cfg *Config) map[string]string {
	values := make(map[string]string)
	if cfg == nil {
		return values
	}
	if cfg.DDNS.TokenRef.Ref != "" {
		values[cfg.DDNS.TokenRef.Ref] = cfg.DDNS.Token
	}
	if cfg.CaptchaSolver.APIKeyRef.Ref != "" {
		values[cfg.CaptchaSolver.APIKeyRef.Ref] = cfg.CaptchaSolver.APIKey
	}
	for _, node := range cfg.ProxyNodes {
		if node.PasswordRef.Ref != "" {
			values[node.PasswordRef.Ref] = node.Password
		}
	}
	return values
}

func secretRefSet(cfg *Config) map[string]struct{} {
	refs := make(map[string]struct{})
	if cfg == nil {
		return refs
	}
	if cfg.DDNS.TokenRef.Ref != "" {
		refs[cfg.DDNS.TokenRef.Ref] = struct{}{}
	}
	if cfg.CaptchaSolver.APIKeyRef.Ref != "" {
		refs[cfg.CaptchaSolver.APIKeyRef.Ref] = struct{}{}
	}
	for _, node := range cfg.ProxyNodes {
		if node.PasswordRef.Ref != "" {
			refs[node.PasswordRef.Ref] = struct{}{}
		}
	}
	return refs
}

func (m *Manager) retireSupersededSecretRefs(previous, committed *Config) {
	if m.secretStore == nil || previous == nil {
		return
	}
	oldRefs := secretRefSet(previous)
	newRefs := secretRefSet(committed)
	for ref := range oldRefs {
		if _, retained := newRefs[ref]; retained {
			continue
		}
		_ = m.secretStore.Delete(context.Background(), ref)
	}
}

func (m *Manager) deleteSecretRefsBestEffort(refs []string) {
	if m.secretStore == nil {
		return
	}
	for _, ref := range refs {
		if ref != "" {
			_ = m.secretStore.Delete(context.Background(), ref)
		}
	}
}

func (m *Manager) hydrateReferencedSecrets(cfg *Config) error {
	if err := m.hydrateSecret(cfg.DDNS.TokenRef, &cfg.DDNS.Token); err != nil {
		return err
	}
	if err := m.hydrateSecret(cfg.CaptchaSolver.APIKeyRef, &cfg.CaptchaSolver.APIKey); err != nil {
		return err
	}
	for i := range cfg.ProxyNodes {
		if err := m.hydrateSecret(cfg.ProxyNodes[i].PasswordRef, &cfg.ProxyNodes[i].Password); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) hydrateSecret(ref secrets.SecretRef, value *string) error {
	if ref.Ref == "" {
		return nil
	}
	if *value != "" {
		return errors.New("configuration has both inline and referenced secret")
	}
	if m.secretStore == nil {
		return secrets.ErrNativeStoreUnavailable
	}
	if err := secrets.ValidateStoreRef(m.secretStore, ref, true); err != nil {
		return err
	}
	secret, err := m.secretStore.Get(context.Background(), ref.Ref)
	if err != nil {
		return err
	}
	*value = string(secret)
	return nil
}

// Get returns the currently loaded configuration.
func (m *Manager) Get() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.deepCopy(m.current)
}

// GetWithRevision returns an immutable caller-owned snapshot together with the
// revision that must be supplied to SaveIfRevision for compare-and-swap.
func (m *Manager) GetWithRevision() (*Config, uint64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.deepCopy(m.current), m.revision
}

// Revision returns the current in-process configuration revision.
func (m *Manager) Revision() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.revision
}

// deepCopy returns a caller-owned clone of every mutable aggregate in Config.
func (m *Manager) deepCopy(src *Config) *Config {
	if src == nil {
		return nil
	}
	copy := *src
	if src.ProxyNodes != nil {
		copy.ProxyNodes = make([]ProxyNodeConfig, len(src.ProxyNodes))
		for i, n := range src.ProxyNodes {
			copy.ProxyNodes[i] = n
		}
	}
	if src.DecoyTraffic.Targets != nil {
		copy.DecoyTraffic.Targets = append([]string(nil), src.DecoyTraffic.Targets...)
	}
	if src.UpdateAdmission.TrustedKeys != nil {
		copy.UpdateAdmission.TrustedKeys = make(map[string]string, len(src.UpdateAdmission.TrustedKeys))
		for key, value := range src.UpdateAdmission.TrustedKeys {
			copy.UpdateAdmission.TrustedKeys[key] = value
		}
	}
	return &copy
}
