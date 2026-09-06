// Package mobilebind provides a gomobile-compatible binding layer for the
// LumiNet proxy engine. It re-exports types that are already gobind-safe and
// wraps incompatible functions (too many return values, wrong second-return
// type) behind JSON-returning wrappers.
//
// Bind this package instead of proxy:
//
//	gomobile bind -target=android github.com/maybeknott/luminet/internal/adapters/mobilebind
package mobilebind

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/maybeknott/luminet/internal/integrations/captchaclient"
	"github.com/maybeknott/luminet/internal/platform/mobilehost"
	"github.com/maybeknott/luminet/internal/protocols/tarpit"
	"github.com/maybeknott/luminet/internal/protocols/tlsfragment"
	"github.com/maybeknott/luminet/internal/runtime/mobilecore"
	"github.com/maybeknott/luminet/internal/runtime/runtimecore"
	"github.com/maybeknott/luminet/internal/runtime/safety"
	"github.com/maybeknott/luminet/internal/runtime/warp"
)

// CaptivePortalHandler is implemented by the mobile host to receive captive portal redirect events.
type CaptivePortalHandler interface {
	OnCaptivePortalDetected(redirectURL string)
}

// RegisterCaptivePortalHandler registers a callback handler for captive portal redirection.
func RegisterCaptivePortalHandler(handler CaptivePortalHandler) {
	mobilehost.SetCaptivePortalCallback(func(redirectURL string) {
		if handler != nil {
			handler.OnCaptivePortalDetected(redirectURL)
		}
	})
}

// ── Re-exported gobind-compatible interfaces ────────────────────────────────
// These interfaces only have methods with ≤2 return values where the second
// (if present) is int, bool, or error — all acceptable to gobind.

// CoreCallbackHandler defines the JVM/iOS callback interface.
type CoreCallbackHandler = mobilecore.CoreCallbackHandler

// SocketProtector provides a callback for exempting sockets from VPN routing.
type SocketProtector = mobilehost.SocketProtector

// ProcessFinder provides process identification for Android routing.
type ProcessFinder = mobilehost.ProcessFinder

// CoreController manages the EvasionTunnel server lifecycle.
type CoreController = mobilecore.CoreController

// ── Re-exported gobind-compatible functions ─────────────────────────────────

// NewCoreController initializes and returns a CoreController.
func NewCoreController(s CoreCallbackHandler) *CoreController {
	return mobilecore.NewCoreController(s)
}

// VPNEngine owns one mobile VPN lifecycle. Android transfers a detached TUN
// descriptor to Start; CoreController then owns that descriptor until startup
// fails or Stop completes. Keeping this wrapper thin preserves the existing
// CoreController compatibility API as the single runtime authority.
type VPNEngine struct {
	mu         sync.Mutex
	controller *mobilecore.CoreController
}

// NewVPNEngine creates an independent mobile VPN lifecycle wrapper.
func NewVPNEngine() *VPNEngine {
	return &VPNEngine{controller: mobilecore.NewCoreController(nil)}
}

// Start transfers ownership of tunFd to the Go runtime and starts the proxy
// core plus the userspace TUN adapter. int32 is deliberate: gobind maps it to
// Java/Kotlin int, matching ParcelFileDescriptor.detachFd().
func (e *VPNEngine) Start(tunFd int32, config string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.controller == nil {
		e.controller = mobilecore.NewCoreController(nil)
	}
	return e.controller.StartLoop(config, tunFd)
}

// Stop tears down the userspace TUN adapter and proxy core.
func (e *VPNEngine) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.controller == nil {
		return nil
	}
	return e.controller.StopLoop()
}

// IsRunning reports whether the shared evasion manager is active.
func (e *VPNEngine) IsRunning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return mobilecore.IsRunning()
}

// CheckVersionX returns the version tag of the native library.
func CheckVersionX() string {
	return mobilecore.CheckVersionX()
}

// ResolveDNS resolves a host address securely via the custom DoH/DoT resolver.
func ResolveDNS(host string) string {
	return mobilecore.ResolveDNS(host)
}

// OptimizeMemoryForMobile overrides GC thresholds for limited environments.
func OptimizeMemoryForMobile() {
	mobilecore.OptimizeMemoryForMobile()
}

// TriggerGC frees heap nodes back to mobile system handlers.
func TriggerGC() {
	mobilecore.TriggerGC()
}

// InitCoreEnv sets up standard mobile assets filesystem locations.
func InitCoreEnv(envPath string, key string) {
	mobilecore.InitCoreEnv(envPath, key)
}

// RegisterSocketProtector registers the socket protector interface callback.
func RegisterSocketProtector(protector SocketProtector) {
	mobilehost.RegisterSocketProtector(protector)
}

// RegisterProcessFinder registers the Android process finder.
func RegisterProcessFinder(finder ProcessFinder) {
	mobilehost.RegisterProcessFinder(finder)
}

// ProtectSocket calls the registered socket protector interface to exclude the FD.
func ProtectSocket(fd int) bool {
	return mobilehost.ProtectSocket(fd)
}

// FindProcessConnection retrieves the owning UID for process-based routing.
func FindProcessConnection(network, srcIP string, srcPort int, destIP string, destPort int) int {
	return mobilehost.FindProcessConnection(network, srcIP, srcPort, destIP, destPort)
}

// ── JSON wrappers for gobind-incompatible functions ─────────────────────────
// These wrap proxy functions that violate gobind rules (too many return values
// or second return value is not error) behind JSON string returns.

func StatusJSON() (string, error) {
	mobileCfg, running := mobilecore.Status()

	statusMap := struct {
		mobilecore.MobileConfig
		Running bool `json:"running"`
	}{
		MobileConfig: mobileCfg,
		Running:      running,
	}

	data, err := json.Marshal(statusMap)
	if err != nil {
		return "", fmt.Errorf("mobilebind: failed to marshal status: %w", err)
	}
	return string(data), nil
}

// GenerateWireGuardKeyPairJSON generates a WireGuard key pair and returns it
// as a JSON object {"public_key":"...","private_key":"..."}.
func GenerateWireGuardKeyPairJSON() (string, error) {
	pub, priv, err := warp.GenerateWireGuardKeyPair()
	if err != nil {
		return "", fmt.Errorf("mobilebind: keygen failed: %w", err)
	}
	result := map[string]string{"public_key": pub, "private_key": priv}
	data, jsonErr := json.Marshal(result)
	if jsonErr != nil {
		return "", fmt.Errorf("mobilebind: failed to marshal keypair: %w", jsonErr)
	}
	return string(data), nil
}

// ExtractSiteKeyJSON extracts a CAPTCHA sitekey from HTML and returns it as
// JSON {"sitekey":"...","captcha_type":"..."}.
// Wraps captchaclient.ExtractSiteKey() which returns (string, string) — gobind
// requires second value to be error.
func ExtractSiteKeyJSON(html string) (string, error) {
	sitekey, captchaType := captchaclient.ExtractSiteKey(html)
	result := map[string]string{"sitekey": sitekey, "captcha_type": captchaType}
	data, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("mobilebind: failed to marshal sitekey: %w", err)
	}
	return string(data), nil
}

// TlsSNIHostRangeJSON parses a TLS ClientHello and returns the SNI hostname
// byte range as JSON {"start":N,"end":M}.
// Wraps tlsfragment.SNIHostRange() which returns (int, int) — gobind requires
// second value to be error.
func TlsSNIHostRangeJSON(data []byte) (string, error) {
	start, end := tlsfragment.SNIHostRange(data)
	result := map[string]int{"start": start, "end": end}
	out, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("mobilebind: failed to marshal range: %w", err)
	}
	return string(out), nil
}

// IsRunning returns whether the evasion tunnel is currently active.
// Convenience method that avoids requiring the full StatusJSON parse.
func IsRunning() bool {
	jsonStr, err := StatusJSON()
	if err != nil {
		return false
	}
	var result map[string]interface{}
	if json.Unmarshal([]byte(jsonStr), &result) != nil {
		return false
	}
	runningVal, ok := result["running"].(bool)
	return ok && runningVal
}

// GetSafetyPolicyJSON returns the current safety governor settings as a JSON string.
func GetSafetyPolicyJSON() (string, error) {
	governor := safety.GetGovernor()
	settings := safety.DefaultSettings()
	status := map[string]interface{}{
		"respect_safety":          settings.RespectSafety,
		"authorization_confirmed": settings.AuthorizationConfirmed,
		"rate_ceiling":            settings.RateCeiling,
		"audit_log_path":          governor.AuditLogPath,
	}
	data, err := json.Marshal(status)
	if err != nil {
		return "", fmt.Errorf("mobilebind: failed to marshal safety policy: %w", err)
	}
	return string(data), nil
}

// ApplySafetyPolicyJSON validates a target under safety policies and returns approval status as JSON.
// JSON keys: target (string), respect_safety (bool), authorization_confirmed (bool), rate_ceiling (int)
func ApplySafetyPolicyJSON(configJSON string) (string, error) {
	var req struct {
		Target                 string `json:"target"`
		RespectSafety          bool   `json:"respect_safety"`
		AuthorizationConfirmed bool   `json:"authorization_confirmed"`
		RateCeiling            int    `json:"rate_ceiling"`
	}
	if err := json.Unmarshal([]byte(configJSON), &req); err != nil {
		return "", fmt.Errorf("mobilebind: invalid policy JSON: %w", err)
	}

	if req.Target == "" {
		return "", fmt.Errorf("mobilebind: safety target is required")
	}

	settings := safety.Settings{
		RespectSafety:          req.RespectSafety,
		AuthorizationConfirmed: req.AuthorizationConfirmed,
		RateCeiling:            req.RateCeiling,
	}
	validationErr := safety.GetGovernor().ValidateScan(req.Target, settings)
	result := map[string]interface{}{
		"approved":                validationErr == nil,
		"target":                  req.Target,
		"respect_safety":          settings.RespectSafety,
		"authorization_confirmed": settings.AuthorizationConfirmed,
		"rate_ceiling":            settings.RateCeiling,
	}
	if validationErr != nil {
		result["error"] = validationErr.Error()
	}
	data, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("mobilebind: failed to marshal policy result: %w", err)
	}
	return string(data), nil
}

// GetTarpitStatusJSON returns the current TCP tarpit server status as a JSON string.
func GetTarpitStatusJSON() (string, error) {
	server := tarpit.GetTarpitServer()
	status := map[string]interface{}{
		"running": server.IsRunning(),
		"address": server.ListenAddr(),
	}
	data, err := json.Marshal(status)
	if err != nil {
		return "", fmt.Errorf("mobilebind: failed to marshal tarpit status: %w", err)
	}
	return string(data), nil
}

// StartProxyEngineJSON starts a proxy engine of the specified type.
// engineType can be "tor" or "psiphon".
// Returns a JSON status string or error.
func StartProxyEngineJSON(engineType string, socksPort int, upstreamProxy string) (string, error) {
	status, err := runtimecore.DefaultManager().Start(runtimecore.Request{
		Engine: runtimecore.Engine(engineType), SocksPort: socksPort, UpstreamProxy: upstreamProxy,
	})
	if err != nil {
		return "", fmt.Errorf("mobilebind: failed to start proxy engine: %w", err)
	}

	result := map[string]interface{}{
		"status":     "started",
		"engine":     engineType,
		"socks_port": status.SocksPort,
	}
	data, jsonErr := json.Marshal(result)
	if jsonErr != nil {
		return "", fmt.Errorf("mobilebind: failed to marshal start response: %w", jsonErr)
	}
	return string(data), nil
}

// StopProxyEngine stops the specified proxy engine.
func StopProxyEngine(engineType string) {
	_, _ = runtimecore.DefaultManager().Stop(runtimecore.Engine(engineType))
}
