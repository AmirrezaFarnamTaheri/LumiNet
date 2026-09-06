package proxy

import (
	"fmt"
	"strings"
	"sync"

	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

const (
	defaultSubscriptionSocksPort = 10808
	minSubscriptionSocksPort     = 1024
	maxSubscriptionSocksPort     = 65535
)

type subscriptionRuntimeInstance interface {
	Stop() error
	IsRunning() bool
}

type subscriptionRuntimeStarter func(*proxyconfig.ProxyConfig, int) (subscriptionRuntimeInstance, error)

// SubscriptionRuntimeStatus is the non-secret ownership view of the one
// explicitly activated subscription node.
type SubscriptionRuntimeStatus struct {
	Active    bool   `json:"active"`
	ProfileID string `json:"profile_id,omitempty"`
	NodeID    string `json:"node_id,omitempty"`
	SocksPort int    `json:"socks_port,omitempty"`
}

type activeSubscriptionRuntime struct {
	status   SubscriptionRuntimeStatus
	instance subscriptionRuntimeInstance
}

// SubscriptionRuntime owns at most one explicit local SOCKS session created
// from a materialized subscription node. It never mutates the OS proxy.
type SubscriptionRuntime struct {
	mu      sync.Mutex
	starter subscriptionRuntimeStarter
	active  *activeSubscriptionRuntime
}

func NewSubscriptionRuntime(core *CoreManager) *SubscriptionRuntime {
	if core == nil {
		core = NewCoreManager(CoreTypeAuto, "")
	}
	return newSubscriptionRuntime(func(cfg *proxyconfig.ProxyConfig, port int) (subscriptionRuntimeInstance, error) {
		return core.RunTempInstance(cfg, port)
	})
}

func newSubscriptionRuntime(starter subscriptionRuntimeStarter) *SubscriptionRuntime {
	return &SubscriptionRuntime{starter: starter}
}

func (r *SubscriptionRuntime) Activate(profileID, nodeID string, cfg *proxyconfig.ProxyConfig, socksPort int) (SubscriptionRuntimeStatus, error) {
	profileID = strings.TrimSpace(profileID)
	nodeID = strings.TrimSpace(nodeID)
	if profileID == "" || nodeID == "" {
		return SubscriptionRuntimeStatus{}, fmt.Errorf("profile id and node id are required")
	}
	if cfg == nil {
		return SubscriptionRuntimeStatus{}, fmt.Errorf("subscription node config is required")
	}
	if socksPort == 0 {
		socksPort = defaultSubscriptionSocksPort
	}
	if socksPort < minSubscriptionSocksPort || socksPort > maxSubscriptionSocksPort {
		return SubscriptionRuntimeStatus{}, fmt.Errorf("subscription SOCKS port must be between %d and %d", minSubscriptionSocksPort, maxSubscriptionSocksPort)
	}
	if r.starter == nil {
		return SubscriptionRuntimeStatus{}, fmt.Errorf("subscription runtime starter is unavailable")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active != nil {
		if r.active.instance != nil && r.active.instance.IsRunning() {
			return r.active.status, fmt.Errorf("subscription runtime already active for profile %q node %q", r.active.status.ProfileID, r.active.status.NodeID)
		}
		// A dead process no longer owns runtime authority. Best-effort Stop also
		// removes the temporary core config if the implementation supports it.
		if r.active.instance != nil {
			_ = r.active.instance.Stop()
		}
		r.active = nil
	}

	instance, err := r.starter(cfg, socksPort)
	if err != nil {
		return SubscriptionRuntimeStatus{}, fmt.Errorf("start subscription runtime: %w", err)
	}
	if instance == nil {
		return SubscriptionRuntimeStatus{}, fmt.Errorf("start subscription runtime returned no process")
	}
	status := SubscriptionRuntimeStatus{Active: true, ProfileID: profileID, NodeID: nodeID, SocksPort: socksPort}
	r.active = &activeSubscriptionRuntime{status: status, instance: instance}
	return status, nil
}

func (r *SubscriptionRuntime) Stop(profileID, nodeID string) error {
	profileID = strings.TrimSpace(profileID)
	nodeID = strings.TrimSpace(nodeID)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil {
		return nil
	}
	if r.active.status.ProfileID != profileID || r.active.status.NodeID != nodeID {
		return fmt.Errorf("subscription runtime ownership mismatch")
	}
	if r.active.instance != nil {
		if err := r.active.instance.Stop(); err != nil {
			return fmt.Errorf("stop subscription runtime: %w", err)
		}
	}
	r.active = nil
	return nil
}

func (r *SubscriptionRuntime) Status() SubscriptionRuntimeStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil {
		return SubscriptionRuntimeStatus{}
	}
	if r.active.instance == nil || !r.active.instance.IsRunning() {
		if r.active.instance != nil {
			_ = r.active.instance.Stop()
		}
		r.active = nil
		return SubscriptionRuntimeStatus{}
	}
	return r.active.status
}

// Close stops the currently owned runtime, if any. Shutdown is intentionally
// not owner-filtered because the daemon itself owns the lifecycle boundary.
func (r *SubscriptionRuntime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil {
		return nil
	}
	if r.active.instance != nil {
		if err := r.active.instance.Stop(); err != nil {
			return fmt.Errorf("stop subscription runtime: %w", err)
		}
	}
	r.active = nil
	return nil
}
