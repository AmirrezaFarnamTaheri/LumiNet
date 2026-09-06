// Package android provides Go functionality for Android desktop components.
package android

import (
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
)

// CellSignalInfo holds LTE/5G signal metrics gathered from Android telephony.
type CellSignalInfo struct {
	Technology   string // "LTE", "NR", "UMTS", "GSM"
	RSRP         int    // Reference signal received power (dBm)
	RSRQ         int    // Reference signal received quality (dB)
	SINR         int    // Signal-to-interference-plus-noise ratio (dB)
	NetworkType  string // e.g. "LTE_CA", "NR_NSA"
	DataRxBytes  int64
	DataTxBytes  int64
}

// TelephonyDiagnostic collects Android cell telemetry, LTE/5G signal
// metrics, and mobile data usage counters.
type TelephonyDiagnostic struct {
	// InterfaceName is the mobile data interface (e.g. "rmnet_data0").
	InterfaceName string
}

func NewTelephonyDiagnostic() *TelephonyDiagnostic {
	return &TelephonyDiagnostic{InterfaceName: "rmnet_data0"}
}

// Diagnose collects current cell signal and data usage via Android shell commands.
// On non-Android hosts, it returns a placeholder result and logs a warning.
func (t *TelephonyDiagnostic) Diagnose() (*CellSignalInfo, error) {
	info := &CellSignalInfo{}

	// Read network interface stats from /proc/net/dev
	out, err := exec.Command("cat", "/proc/net/dev").Output()
	if err != nil {
		slog.Warn("TelephonyDiagnostic: /proc/net/dev unavailable", "err", err)
		return info, nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, t.InterfaceName+":") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) >= 10 {
				info.DataRxBytes, _ = strconv.ParseInt(fields[1], 10, 64)
				info.DataTxBytes, _ = strconv.ParseInt(fields[9], 10, 64)
			}
		}
	}

	// Read signal strength via dumpsys telephony.registry (Android only)
	sigOut, err := exec.Command("dumpsys", "telephony.registry").Output()
	if err != nil {
		slog.Warn("TelephonyDiagnostic: dumpsys unavailable", "err", err)
		return info, nil
	}
	lines := strings.Split(string(sigOut), "\n")
	for _, line := range lines {
		l := strings.TrimSpace(line)
		if strings.Contains(l, "LTE") {
			info.Technology = "LTE"
		} else if strings.Contains(l, "NR") {
			info.Technology = "NR"
		}
		if strings.HasPrefix(l, "rsrp=") {
			if v, err := strconv.Atoi(strings.TrimPrefix(l, "rsrp=")); err == nil {
				info.RSRP = v
			}
		}
	}

	slog.Info("TelephonyDiagnostic: metrics collected",
		"technology", info.Technology,
		"rsrp", info.RSRP,
		"rx_bytes", info.DataRxBytes,
		"tx_bytes", info.DataTxBytes,
	)
	return info, nil
}

// DataUsage returns current interface RX/TX byte counts.
func (t *TelephonyDiagnostic) DataUsage() (rxBytes, txBytes int64, err error) {
	info, err := t.Diagnose()
	if err != nil {
		return 0, 0, fmt.Errorf("TelephonyDiagnostic.DataUsage: %w", err)
	}
	return info.DataRxBytes, info.DataTxBytes, nil
}
