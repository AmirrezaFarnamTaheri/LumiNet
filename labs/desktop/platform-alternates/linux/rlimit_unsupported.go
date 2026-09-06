//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd

package linux

import "errors"

// SetResourceLimits is a no-op on non-Unix platforms.
func (p *PayloadEditor) SetResourceLimits(maxFiles uint64, maxMemBytes uint64) error {
	return errors.New("PayloadEditor.SetResourceLimits: not supported on this platform")
}
