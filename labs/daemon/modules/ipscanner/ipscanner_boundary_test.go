package ipscanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScannerDoesNotDependOnProxyRuntime(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("ipscanner.go"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(source), "internal/proxy") || strings.Contains(string(source), "quicSpeedTest") {
		t.Fatal("ip scanner must not use proxy runtime or simulated QUIC throughput")
	}
}
