// doctor — CLI wrapper for the doctor readiness check.
//
// Addresses O-02: Metrics and Doctor Command Need to Become Readiness Gates.
//
// Usage:
//
//	luminet doctor [--url http://127.0.0.1:9090] [--json]
//
// The command connects to a running luminet daemon and hits /api/doctor.
// If the daemon is not reachable it reports an offline status.
// Exit code 0 = healthy, 1 = unhealthy, 2 = unreachable.
package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var (
	doctorURL     string
	doctorJSONOut bool
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run readiness checks against a running luminet daemon",
	Long: `doctor connects to the luminet daemon and executes all registered
readiness checks. It prints a structured report and exits with:
  0 — all checks passed
  1 — one or more checks failed
  2 — daemon unreachable`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDoctor(doctorURL, doctorJSONOut)
	},
}

func init() {
	doctorCmd.Flags().StringVar(&doctorURL, "url", "http://127.0.0.1:9090", "Daemon base URL")
	doctorCmd.Flags().BoolVar(&doctorJSONOut, "json", false, "Output JSON instead of table")
	rootCmd.AddCommand(doctorCmd)
}

// doctorReport mirrors api.DoctorReport for JSON unmarshalling.
type doctorReport struct {
	Timestamp time.Time `json:"timestamp"`
	Healthy   bool      `json:"healthy"`
	GoVersion string    `json:"go_version"`
	GOOS      string    `json:"goos"`
	GOARCH    string    `json:"goarch"`
	Checks    []struct {
		Name    string        `json:"name"`
		OK      bool          `json:"ok"`
		Message string        `json:"message"`
		Latency time.Duration `json:"latency_ns"`
	} `json:"checks"`
}

func runDoctor(baseURL string, jsonOut bool) error {
	url := baseURL + "/api/doctor"
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ daemon unreachable: %v\n", err)
		os.Exit(2)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDaemonResponseBytes+1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ failed to read response: %v\n", err)
		os.Exit(2)
	}
	if len(body) > maxDaemonResponseBytes {
		fmt.Fprintf(os.Stderr, "✗ daemon response exceeds size limit\n")
		os.Exit(2)
	}
	var report doctorReport
	if err := json.Unmarshal(body, &report); err != nil {
		fmt.Fprintf(os.Stderr, "✗ failed to decode response: %v\n", err)
		os.Exit(2)
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	} else {
		printDoctorTable(report)
	}

	if !report.Healthy {
		os.Exit(1)
	}
	return nil
}

func printDoctorTable(r doctorReport) {
	status := "✓ HEALTHY"
	if !r.Healthy {
		status = "✗ UNHEALTHY"
	}
	fmt.Printf("LumiNet Doctor  %s  (daemon %s %s/%s)\n\n",
		status, r.GoVersion, r.GOOS, r.GOARCH)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CHECK\tSTATUS\tLATENCY\tMESSAGE")
	fmt.Fprintln(w, "─────\t──────\t───────\t───────")
	for _, c := range r.Checks {
		s := "OK"
		if !c.OK {
			s = "FAIL"
		}
		lat := time.Duration(c.Latency).Round(time.Microsecond)
		fmt.Fprintf(w, "%s\t%s\t%v\t%s\n", c.Name, s, lat, c.Message)
	}
	_ = w.Flush()
	fmt.Println()
}
