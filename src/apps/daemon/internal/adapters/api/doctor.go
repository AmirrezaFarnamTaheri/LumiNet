// Package api — Doctor readiness command / endpoint.
//
// Addresses O-02: Metrics and Doctor Command Need to Become Readiness Gates.
//
// /api/doctor runs a set of named checks and returns a structured JSON
// report. The HTTP status is 200 if all checks pass, 503 if any fail.
// The same checks run when `luminet doctor` is invoked from the CLI
// (see server/cmd/doctor.go for the CLI wrapper).
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"runtime"
	"time"
)

// CheckResult is the outcome of a single readiness check.
type CheckResult struct {
	Name    string        `json:"name"`
	OK      bool          `json:"ok"`
	Message string        `json:"message,omitempty"`
	Latency time.Duration `json:"latency_ns,omitempty"`
}

// DoctorReport is the full readiness report returned by /api/doctor.
type DoctorReport struct {
	Timestamp time.Time     `json:"timestamp"`
	Healthy   bool          `json:"healthy"`
	Checks    []CheckResult `json:"checks"`
	GoVersion string        `json:"go_version"`
	GOOS      string        `json:"goos"`
	GOARCH    string        `json:"goarch"`
}

// Checker is a named health check.
type Checker interface {
	Name() string
	Check(ctx context.Context) CheckResult
}

// CheckerFunc adapts a function to the Checker interface.
type CheckerFunc struct {
	name string
	fn   func(context.Context) CheckResult
}

func NewChecker(name string, fn func(context.Context) CheckResult) Checker {
	return CheckerFunc{name: name, fn: fn}
}

func (c CheckerFunc) Name() string                          { return c.name }
func (c CheckerFunc) Check(ctx context.Context) CheckResult { return c.fn(ctx) }

// DoctorHandler is the /api/doctor HTTP handler.
type DoctorHandler struct {
	checkers []Checker
}

// NewDoctorHandler creates a handler with the given checkers.
func NewDoctorHandler(checkers ...Checker) *DoctorHandler {
	return &DoctorHandler{checkers: checkers}
}

// RegisterChecker adds a checker at runtime (e.g. from subsystem init).
func (h *DoctorHandler) RegisterChecker(c Checker) {
	h.checkers = append(h.checkers, c)
}

// ServeHTTP implements http.Handler.
func (h *DoctorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	report := h.Run(r.Context())
	status := http.StatusOK
	if !report.Healthy {
		status = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(report)
}

// Run executes all checks and returns the report. Used by both HTTP and CLI.
func (h *DoctorHandler) Run(ctx context.Context) DoctorReport {
	report := DoctorReport{
		Timestamp: time.Now().UTC(),
		Healthy:   true,
		GoVersion: runtime.Version(),
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
	}

	for _, c := range h.checkers {
		start := time.Now()
		result := c.Check(ctx)
		result.Latency = time.Since(start)
		if result.Name == "" {
			result.Name = c.Name()
		}
		report.Checks = append(report.Checks, result)
		if !result.OK {
			report.Healthy = false
		}
	}

	return report
}

// AlwaysOKChecker is a no-op checker for testing and bootstrapping.
var AlwaysOKChecker = NewChecker("self", func(context.Context) CheckResult {
	return CheckResult{Name: "self", OK: true, Message: "doctor is alive"}
})
