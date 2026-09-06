// Package telemetry implements observation and diagnostic endpoints.
package telemetry

import (
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ObservedEndpoint captures an API endpoint inferred from traffic.
type ObservedEndpoint struct {
	Method      string
	Path        string
	StatusCodes map[int]int
	LastSeen    time.Time
	SampleCount int
}

// OpenAPIGen observes HTTP traffic and generates an OpenAPI 3.0 spec skeleton.
type OpenAPIGen struct {
	mu        sync.Mutex
	endpoints map[string]*ObservedEndpoint
}

var (
	uuidSegRe = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	numSegRe  = regexp.MustCompile(`/\d+(/|$)`)
)

func NewOpenAPIGen() *OpenAPIGen {
	return &OpenAPIGen{endpoints: make(map[string]*ObservedEndpoint)}
}

// Observe records one HTTP request/response pair.
func (o *OpenAPIGen) Observe(method, path string, status int) {
	path = uuidSegRe.ReplaceAllString(path, "{uuid}")
	path = numSegRe.ReplaceAllStringFunc(path, func(s string) string {
		return strings.TrimRight(s, "/") + "/{id}/"
	})
	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx]
	}
	key := method + " " + path
	o.mu.Lock()
	defer o.mu.Unlock()
	ep, ok := o.endpoints[key]
	if !ok {
		ep = &ObservedEndpoint{Method: method, Path: path, StatusCodes: make(map[int]int)}
		o.endpoints[key] = ep
	}
	ep.StatusCodes[status]++
	ep.LastSeen = time.Now().UTC()
	ep.SampleCount++
}

// ObserveRequest records from an *http.Request and response status.
func (o *OpenAPIGen) ObserveRequest(r *http.Request, status int) {
	o.Observe(r.Method, r.URL.Path, status)
}

// Generate produces an OpenAPI 3.0 YAML spec from observed endpoints.
func (o *OpenAPIGen) Generate(title, version string) string {
	o.mu.Lock()
	keys := make([]string, 0, len(o.endpoints))
	for k := range o.endpoints {
		keys = append(keys, k)
	}
	o.mu.Unlock()
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("openapi: \"3.0.3\"\ninfo:\n  title: %q\n  version: %q\npaths:\n", title, version))
	for _, k := range keys {
		o.mu.Lock()
		ep := o.endpoints[k]
		o.mu.Unlock()
		sb.WriteString(fmt.Sprintf("  %s:\n    %s:\n      responses:\n", ep.Path, strings.ToLower(ep.Method)))
		for code := range ep.StatusCodes {
			sb.WriteString(fmt.Sprintf("        \"%d\":\n          description: observed\n", code))
		}
	}
	slog.Info("OpenAPIGen: spec generated", "endpoints", len(keys))
	return sb.String()
}

// EndpointCount returns the number of unique endpoints observed.
func (o *OpenAPIGen) EndpointCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.endpoints)
}