package system

import (
	"context"
	"runtime"
	"testing"

	"github.com/maybeknott/luminet/internal/platform"
)

func TestSystemAdapterReportsTunCapabilityTruthfully(t *testing.T) {
	status := (&SystemAdapter{}).Status(context.Background())
	hasTunControl := false
	for _, capability := range status.Capabilities {
		if capability == platform.CapabilityTunControl {
			hasTunControl = true
			break
		}
	}
	if hasTunControl != (runtime.GOOS == "windows") {
		t.Fatalf("tun capability mismatch for %s: %v", runtime.GOOS, hasTunControl)
	}
}
