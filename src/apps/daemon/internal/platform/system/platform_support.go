package system

import "errors"

// ErrUnsupportedPlatformFeature marks a feature whose implementation is not
// available on the current build target. Callers may use errors.Is to map the
// condition to capability truth instead of reporting a generic runtime failure.
var ErrUnsupportedPlatformFeature = errors.New("feature unsupported on this platform")
