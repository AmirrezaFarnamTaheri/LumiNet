package proxy

import (
	"fmt"
	"os"
	"runtime/debug"
)

// TuneGC dynamically sets GOMEMLIMIT and GOGC for high-performance memory management.
func TuneGC() {
	// Respect GOMEMLIMIT if already set in environment
	if os.Getenv("GOMEMLIMIT") != "" {
		return
	}

	totalMem := getSystemTotalMemory()
	if totalMem > 0 {
		// Set soft limit to 90% of total memory to leave buffer for CGO, threads, etc.
		limit := int64(float64(totalMem) * 0.90)
		debug.SetMemoryLimit(limit)
		fmt.Printf("[GC Tuning] Configured GOMEMLIMIT dynamically to %d MB (90%% of system memory)\n", limit/(1024*1024))
	} else {
		// Fallback memory limit: 1 GiB
		debug.SetMemoryLimit(1024 * 1024 * 1024)
		fmt.Println("[GC Tuning] Configured GOMEMLIMIT to fallback default of 1024 MB")
	}

	// Set GOGC if not already set
	if os.Getenv("GOGC") == "" {
		// Dynamic proxy workloads benefit from aggressive collection of short-lived packet buffers.
		// A GOGC value of 80 strikes a good balance between CPU usage and memory footprint.
		debug.SetGCPercent(80)
		fmt.Println("[GC Tuning] Configured GOGC dynamically to 80")
	}
}
