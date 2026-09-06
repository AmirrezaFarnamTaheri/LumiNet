//go:build !windows && !darwin && !linux

package secrets

import (
	"fmt"
	"runtime"
)

func newPlatformStore() (NativeStore, error) {
	return nil, fmt.Errorf("%w: no native provider for %s", ErrNativeStoreUnavailable, runtime.GOOS)
}
