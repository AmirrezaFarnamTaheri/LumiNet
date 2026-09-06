//go:build linux


package system

import (
	"fmt"
	"runtime"

	"github.com/vishvananda/netns"
)

// NetnsTunnel runs a closure function inside a targeted Linux network namespace.
type NetnsTunnel struct {
	NamespaceName string // e.g. "container_ns"
}

// NewNetnsTunnel creates a new namespace tunnel manager.
func NewNetnsTunnel(nsName string) *NetnsTunnel {
	return &NetnsTunnel{NamespaceName: nsName}
}

// RunInNamespace locks the current OS thread, switches to the target namespace,
// runs the task, and restores the original namespace.
func (t *NetnsTunnel) RunInNamespace(task func() error) error {
	// Lock OS thread to prevent Go runtime from moving this goroutine
	// to another OS thread while we are switched to target namespace.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Get current namespace handle
	originalNs, err := netns.Get()
	if err != nil {
		return fmt.Errorf("netns_tunnel: get current ns: %w", err)
	}
	defer originalNs.Close()

	// Open target namespace
	targetNs, err := netns.GetFromName(t.NamespaceName)
	if err != nil {
		return fmt.Errorf("netns_tunnel: open target ns %s: %w", t.NamespaceName, err)
	}
	defer targetNs.Close()

	// Switch to target namespace
	if err := netns.Set(targetNs); err != nil {
		return fmt.Errorf("netns_tunnel: set target ns: %w", err)
	}

	// Run the closure
	taskErr := task()

	// Switch back to original namespace
	if err := netns.Set(originalNs); err != nil {
		return fmt.Errorf("netns_tunnel: restore original ns: %w", err)
	}

	return taskErr
}
