//go:build !windows

package process

import (
	"errors"
	"testing"
)

func TestUnsupportedStartupFailsClosed(t *testing.T) {
	if StartupSupported() {
		t.Fatal("startup registration reported supported on non-Windows build")
	}
	if IsStartupEnabled() {
		t.Fatal("startup registration reported enabled on unsupported platform")
	}
	for name, err := range map[string]error{
		"enable startup":  EnableStartup(),
		"disable startup": DisableStartup(),
	} {
		if !errors.Is(err, ErrUnsupportedPlatformFeature) {
			t.Fatalf("%s: got %v, want unsupported-platform error", name, err)
		}
	}
}
