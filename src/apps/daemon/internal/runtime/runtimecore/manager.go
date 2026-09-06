package runtimecore

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/maybeknott/luminet/internal/foundation/flowregistry"
	system "github.com/maybeknott/luminet/internal/platform/system"
)

var ErrInvalidRequest = errors.New("invalid runtime-core request")

type Engine string

const (
	EngineTor     Engine = "tor"
	EnginePsiphon Engine = "psiphon"
	EngineSSTP    Engine = "sstp"
	EngineIKEv2   Engine = "ikev2"
)

type TorTransportPlugin struct {
	Name       string
	Executable string
	Args       []string
}

var torTransportExecutableRegistry = map[string][]string{
	"obfs4":     {"lyrebird", "obfs4proxy"},
	"snowflake": {"snowflake-client"},
	"webtunnel": {"webtunnel-client"},
}

// torTransportArgumentRegistry is deliberately narrower than the underlying
// binaries' complete CLI. The privileged API owns bridge-client configuration,
// not arbitrary invocation of an allow-listed executable. Bridge-specific
// broker/ICE/URL material belongs on the validated Bridge line.
var torTransportArgumentRegistry = map[string]map[string]struct{}{
	"obfs4":     {},
	"snowflake": {"-keep-local-addresses": {}},
	"webtunnel": {},
}

type Request struct {
	Engine           Engine
	SocksPort        int
	ControlPort      int
	UpstreamProxy    string
	Server           string
	Username         string
	Password         string
	CACert           string
	AllowCertWarning bool
	PPPOptions       []string
	Identity         string
	RemoteIdentity   string
	Certificate      string
	PrivateKey       string
	LocalTS          string
	RemoteTS         string
	IKEProposals     []string
	ESPProposals     []string
	Bridges          []string
	TransportPlugins []TorTransportPlugin
}

type Status struct {
	Engine    Engine `json:"engine"`
	Running   bool   `json:"running"`
	SocksPort int    `json:"socks_port"`
	Mode      string `json:"mode,omitempty"`
}

type engine interface {
	Start() error
	Stop()
	IsRunning() bool
}

type engineFactory func(Request) (engine, error)
type enginePreflight func(Request) (Request, error)

type activeEngine struct {
	request Request
	engine  engine
}

type Manager struct {
	mu        sync.Mutex
	factory   engineFactory
	preflight enginePreflight
	active    map[Engine]activeEngine
}

var runtimeCoreFlowCoverageOnce sync.Once

func declareRuntimeCoreFlowCoverage() {
	runtimeCoreFlowCoverageOnce.Do(func() {
		for _, c := range []flowregistry.OwnerCoverage{
			{Owner: "runtimecore-tor", Visible: false, Closeable: false, ByteCounters: false, ProcessAttribution: false, DestinationMetadata: false, Notes: []string{"Tor engine lifecycle is authoritative in runtimecore, but per-circuit/per-stream flows are not yet published by the external Tor process."}},
			{Owner: "runtimecore-psiphon", Visible: false, Closeable: false, ByteCounters: false, ProcessAttribution: false, DestinationMetadata: false, Notes: []string{"Psiphon engine lifecycle is authoritative in runtimecore, but external process flows are not yet published."}},
			{Owner: "runtimecore-sstp", Visible: false, Closeable: false, ByteCounters: false, ProcessAttribution: false, DestinationMetadata: false, Notes: []string{"SSTP tunnel lifecycle is authoritative in runtimecore; host traffic inside that tunnel is outside the current flow registry."}},
			{Owner: "runtimecore-ikev2", Visible: false, Closeable: false, ByteCounters: false, ProcessAttribution: false, DestinationMetadata: false, Notes: []string{"IKEv2 tunnel lifecycle is authoritative in runtimecore; host traffic inside that tunnel is outside the current flow registry."}},
		} {
			_ = flowregistry.Default().DeclareOwner(c)
		}
	})
}

func NewManager() *Manager {
	declareRuntimeCoreFlowCoverage()
	return newManagerWithFactoryAndPreflight(productionFactory, productionPreflight)
}

func newManagerWithFactory(factory engineFactory) *Manager {
	return newManagerWithFactoryAndPreflight(factory, nil)
}

func newManagerWithFactoryAndPreflight(factory engineFactory, preflight enginePreflight) *Manager {
	return &Manager{factory: factory, preflight: preflight, active: make(map[Engine]activeEngine)}
}

var defaultManager = NewManager()

func DefaultManager() *Manager { return defaultManager }

func (m *Manager) Start(request Request) (Status, error) {
	req, err := normalizeRequest(request)
	if err != nil {
		return Status{}, err
	}
	// Environment-dependent admission (for example resolving a registered
	// pluggable-transport binary) happens before replacement authority is
	// acquired. A failed preflight must never stop a healthy current engine.
	if m.preflight != nil {
		req, err = m.preflight(req)
		if err != nil {
			return Status{}, err
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var previous *activeEngine
	if current, ok := m.active[req.Engine]; ok {
		if !current.engine.IsRunning() {
			delete(m.active, req.Engine)
		} else if requestsEqual(current.request, req) {
			return statusFor(current.request, true), nil
		} else {
			current.engine.Stop()
			if current.engine.IsRunning() {
				return statusFor(current.request, true), fmt.Errorf("runtime-core %s refused to stop for configuration replacement", req.Engine)
			}
			delete(m.active, req.Engine)
			previous = &current
		}
	}

	started, err := m.startEngineLocked(req)
	if err != nil {
		if previous == nil {
			return Status{}, err
		}
		return m.restorePreviousLocked(*previous, err)
	}
	m.active[req.Engine] = started
	return statusFor(req, true), nil
}

// startEngineLocked constructs and starts one engine without publishing it.
// The caller holds m.mu so publication and replacement remain serialized.
func (m *Manager) startEngineLocked(req Request) (activeEngine, error) {
	eng, err := m.factory(req)
	if err != nil {
		return activeEngine{}, fmt.Errorf("construct runtime-core %s: %w", req.Engine, err)
	}
	if eng == nil {
		return activeEngine{}, fmt.Errorf("runtime-core %s factory returned nil engine", req.Engine)
	}
	if err := eng.Start(); err != nil {
		eng.Stop()
		return activeEngine{}, fmt.Errorf("start runtime-core %s: %w", req.Engine, err)
	}
	if !eng.IsRunning() {
		eng.Stop()
		return activeEngine{}, fmt.Errorf("runtime-core %s exited during startup", req.Engine)
	}
	return activeEngine{request: req, engine: eng}, nil
}

// restorePreviousLocked provides transactional replacement semantics. Once a
// healthy engine has been stopped for a configuration change, a failed new
// start must make a best effort to restore the previous known-good request
// before returning control to the caller.
func (m *Manager) restorePreviousLocked(previous activeEngine, replacementErr error) (Status, error) {
	restored, restoreErr := m.startEngineLocked(previous.request)
	if restoreErr != nil {
		return statusFor(previous.request, false), errors.Join(
			replacementErr,
			fmt.Errorf("restore previous runtime-core %s configuration: %w", previous.request.Engine, restoreErr),
		)
	}
	m.active[previous.request.Engine] = restored
	return statusFor(previous.request, true), fmt.Errorf("%w; previous runtime-core %s configuration restored", replacementErr, previous.request.Engine)
}

func (m *Manager) Stop(kind Engine) (Status, error) {
	defaults, err := defaultRequest(kind)
	if err != nil {
		return Status{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.active[kind]
	if !ok {
		return statusFor(defaults, false), nil
	}
	current.engine.Stop()
	if current.engine.IsRunning() {
		return statusFor(current.request, true), fmt.Errorf("runtime-core %s remained running after stop", kind)
	}
	delete(m.active, kind)
	return statusFor(current.request, false), nil
}

func (m *Manager) Status(kind Engine) (Status, error) {
	defaults, err := defaultRequest(kind)
	if err != nil {
		return Status{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.active[kind]
	if !ok {
		return statusFor(defaults, false), nil
	}
	if !current.engine.IsRunning() {
		delete(m.active, kind)
		return statusFor(current.request, false), nil
	}
	return statusFor(current.request, true), nil
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []error
	for kind, current := range m.active {
		current.engine.Stop()
		if current.engine.IsRunning() {
			errs = append(errs, fmt.Errorf("runtime-core %s remained running after close", kind))
			continue
		}
		delete(m.active, kind)
	}
	return errors.Join(errs...)
}

func requestsEqual(left, right Request) bool {
	return left.Engine == right.Engine &&
		left.SocksPort == right.SocksPort &&
		left.ControlPort == right.ControlPort &&
		left.UpstreamProxy == right.UpstreamProxy &&
		left.Server == right.Server &&
		left.Username == right.Username &&
		left.Password == right.Password &&
		left.CACert == right.CACert &&
		left.AllowCertWarning == right.AllowCertWarning &&
		slices.Equal(left.PPPOptions, right.PPPOptions) &&
		left.Identity == right.Identity && left.RemoteIdentity == right.RemoteIdentity &&
		left.Certificate == right.Certificate && left.PrivateKey == right.PrivateKey &&
		left.LocalTS == right.LocalTS && left.RemoteTS == right.RemoteTS &&
		slices.Equal(left.IKEProposals, right.IKEProposals) && slices.Equal(left.ESPProposals, right.ESPProposals) &&
		slices.Equal(left.Bridges, right.Bridges) && torTransportPluginsEqual(left.TransportPlugins, right.TransportPlugins)
}

func torTransportPluginsEqual(left, right []TorTransportPlugin) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i].Name != right[i].Name || left[i].Executable != right[i].Executable || !slices.Equal(left[i].Args, right[i].Args) {
			return false
		}
	}
	return true
}

func defaultRequest(kind Engine) (Request, error) {
	switch kind {
	case EngineTor:
		return Request{Engine: kind, SocksPort: 10950, ControlPort: 10951}, nil
	case EnginePsiphon:
		return Request{Engine: kind, SocksPort: 10890}, nil
	case EngineSSTP, EngineIKEv2:
		return Request{Engine: kind}, nil
	default:
		return Request{}, fmt.Errorf("%w: unsupported engine %q", ErrInvalidRequest, kind)
	}
}

func normalizeRequest(req Request) (Request, error) {
	if req.Engine != EngineTor && (len(req.Bridges) > 0 || len(req.TransportPlugins) > 0) {
		return Request{}, fmt.Errorf("%w: Tor bridge/transport configuration is only valid for the Tor engine", ErrInvalidRequest)
	}
	switch req.Engine {
	case EngineTor:
		if req.SocksPort == 0 {
			req.SocksPort = 10950
		}
		if req.ControlPort == 0 {
			req.ControlPort = req.SocksPort + 1
		}
		req.Bridges = append([]string(nil), req.Bridges...)
		req.TransportPlugins = cloneTorTransportPluginRequests(req.TransportPlugins)
		for i := range req.TransportPlugins {
			normalized, err := normalizeTorTransportPluginRequest(req.TransportPlugins[i])
			if err != nil {
				return Request{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
			}
			req.TransportPlugins[i] = normalized
		}
		if err := validateTorTransportRequest(req.Bridges, req.TransportPlugins); err != nil {
			return Request{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
		}
	case EnginePsiphon:
		if req.SocksPort == 0 {
			req.SocksPort = 10890
		}
		req.ControlPort = 0
	case EngineSSTP:
		req.SocksPort = 0
		req.ControlPort = 0
		server, err := normalizeSSTPServer(req.Server)
		if err != nil {
			return Request{}, err
		}
		req.Server = server
		if strings.TrimSpace(req.Username) == "" || req.Password == "" {
			return Request{}, fmt.Errorf("%w: SSTP username and password are required", ErrInvalidRequest)
		}
		if len(req.PPPOptions) > 32 {
			return Request{}, fmt.Errorf("%w: too many SSTP PPP options", ErrInvalidRequest)
		}
		for _, option := range req.PPPOptions {
			if strings.TrimSpace(option) == "" || len(option) > 128 || strings.ContainsAny(option, "\r\n\x00") {
				return Request{}, fmt.Errorf("%w: invalid SSTP PPP option", ErrInvalidRequest)
			}
		}
	case EngineIKEv2:
		return normalizeIKEv2Request(req)
	default:
		return Request{}, fmt.Errorf("%w: unsupported engine %q", ErrInvalidRequest, req.Engine)
	}
	if req.Engine != EngineSSTP && req.Engine != EngineIKEv2 && (req.SocksPort <= 0 || req.SocksPort > 65535) {
		return Request{}, fmt.Errorf("%w: invalid SOCKS port %d", ErrInvalidRequest, req.SocksPort)
	}
	if req.Engine == EngineTor && (req.ControlPort <= 0 || req.ControlPort > 65535 || req.ControlPort == req.SocksPort) {
		return Request{}, fmt.Errorf("%w: invalid Tor control port %d", ErrInvalidRequest, req.ControlPort)
	}
	return req, nil
}

func statusFor(req Request, running bool) Status {
	mode := "socks"
	if req.Engine == EngineSSTP || req.Engine == EngineIKEv2 {
		mode = "system-tunnel"
	}
	return Status{Engine: req.Engine, Running: running, SocksPort: req.SocksPort, Mode: mode}
}

// RotateTorIdentity asks the currently running Tor engine to create a fresh
// circuit identity. It never starts Tor implicitly and therefore cannot hide a
// missing runtime dependency behind a mutation.
func (m *Manager) RotateTorIdentity() error {
	m.mu.Lock()
	current, ok := m.active[EngineTor]
	if !ok || !current.engine.IsRunning() {
		m.mu.Unlock()
		return fmt.Errorf("%w: Tor engine is not running", ErrInvalidRequest)
	}
	tor, ok := current.engine.(*torEngine)
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("runtime-core Tor engine does not expose identity rotation")
	}
	return tor.rotateIdentity()
}

func normalizeTorTransportPluginRequest(plugin TorTransportPlugin) (TorTransportPlugin, error) {
	plugin.Name = strings.ToLower(strings.TrimSpace(plugin.Name))
	allowed, ok := torTransportExecutableRegistry[plugin.Name]
	if !ok {
		return TorTransportPlugin{}, fmt.Errorf("unsupported Tor transport %q", plugin.Name)
	}
	plugin.Executable = strings.TrimSpace(plugin.Executable)
	if plugin.Executable == "" {
		plugin.Executable = allowed[0]
	}
	if strings.ContainsAny(plugin.Executable, `/\\`) {
		return TorTransportPlugin{}, fmt.Errorf("Tor transport executable must be an allow-listed binary name, not a path")
	}
	canonicalExecutable := ""
	for _, candidate := range allowed {
		if strings.EqualFold(plugin.Executable, candidate) || strings.EqualFold(plugin.Executable, candidate+".exe") {
			canonicalExecutable = candidate
			break
		}
	}
	if canonicalExecutable == "" {
		return TorTransportPlugin{}, fmt.Errorf("executable %q is not allowed for Tor transport %q", plugin.Executable, plugin.Name)
	}
	plugin.Executable = canonicalExecutable

	allowedArgs := torTransportArgumentRegistry[plugin.Name]
	plugin.Args = append([]string(nil), plugin.Args...)
	for _, arg := range plugin.Args {
		if _, ok := allowedArgs[arg]; !ok {
			return TorTransportPlugin{}, fmt.Errorf("argument %q is not allowed for Tor transport %q", arg, plugin.Name)
		}
	}
	return plugin, nil
}

func validateTorTransportRequest(bridges []string, plugins []TorTransportPlugin) error {
	systemPlugins := make([]system.TorTransportPlugin, len(plugins))
	for i, plugin := range plugins {
		systemPlugins[i] = system.TorTransportPlugin{
			Name:       plugin.Name,
			Executable: plugin.Executable,
			Args:       append([]string(nil), plugin.Args...),
		}
	}
	_, err := system.NewTorConfigBuilder().BridgesWithTransports(bridges, systemPlugins).BuildValidated()
	return err
}

func cloneTorTransportPluginRequests(in []TorTransportPlugin) []TorTransportPlugin {
	out := make([]TorTransportPlugin, len(in))
	for i, plugin := range in {
		out[i] = plugin
		out[i].Args = append([]string(nil), plugin.Args...)
	}
	return out
}
