//go:build !linux

// Package system handles platform-specific parameters, routing, and cert configurations.

package system

import "fmt"

func switchToNamespaceImpl(name string) error {
	return fmt.Errorf("network namespace switching is not supported on this platform")
}
