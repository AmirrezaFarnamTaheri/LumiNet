// Package system handles platform-specific parameters, routing, and cert configurations.

package system

import "fmt"

// NetnsHandle wraps network namespace file descriptors.
type NetnsHandle int

// SwitchToNamespace switches the current thread's network namespace.
// Delegates to platform-specific setns on Linux, returns stub errors elsewhere.
func SwitchToNamespace(name string) error {
	return switchToNamespaceImpl(name)
}

func formatNamespacePath(name string) string {
	return fmt.Sprintf("/run/netns/%s", name)
}
