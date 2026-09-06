package process

import "errors"

// ErrUnsupportedPlatformFeature marks process/startup operations unavailable on this target.
var ErrUnsupportedPlatformFeature = errors.New("process feature unsupported on this platform")
