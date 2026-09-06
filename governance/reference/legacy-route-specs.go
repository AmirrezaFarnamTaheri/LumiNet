// Package api — Five-workflow route registry.
//
// Addresses P-03: Five-Workflow Route Registry.
//
// This file is the single source of truth for all API route paths and their
// metadata. It is used by:
//   - router.go to register handlers
//   - The /api/routes introspection endpoint
//   - The openapi generator (if added later)
//
// Workflow classification:
//   W1 - Scan & Discovery       (network scanning, probing, evidence)
//   W2 - Proxy & Tunnel         (proxy management, routing, subscriptions)
//   W3 - System & Configuration (DNS, NCSI, WFP, TUN, DDNS)
//   W4 - Covert & Intelligence  (covert tracker, traffic accounting)
//   W5 - Observability          (metrics, diagnostics, events, doctor)
package api

// RouteSpec describes a single API endpoint.
type RouteSpec struct {
	Method    string // HTTP method
	Path      string // URL path (using {param} notation)
	Workflow  int    // Workflow number (1–5)
	Tag       string // Short tag for grouping in docs
	Summary   string // One-line description
	Public    bool   // True if accessible without auth (rare)
	AdminOnly bool   // True if requires admin-level API key
}

// Routes is the complete registry of all LumiNet API routes.
// Order is significant: routes are matched top-to-bottom in the router.
var Routes = []RouteSpec{
	// ─── W1: Scan & Discovery ──────────────────────────────────────────────
	{Method: "POST",   Path: "/api/scan/start",           Workflow: 1, Tag: "scan",     Summary: "Start a scan job"},
	{Method: "GET",    Path: "/api/scan/{job_id}/status", Workflow: 1, Tag: "scan",     Summary: "Get scan job status"},
	{Method: "GET",    Path: "/api/scan/{job_id}/results",Workflow: 1, Tag: "scan",     Summary: "Stream scan results (JSONL)"},
	{Method: "DELETE", Path: "/api/scan/{job_id}",        Workflow: 1, Tag: "scan",     Summary: "Cancel a running scan"},
	{Method: "GET",    Path: "/api/evidence/{job_id}",    Workflow: 1, Tag: "evidence", Summary: "List probe evidence for a job"},
	{Method: "GET",    Path: "/api/evidence/{job_id}/nmap", Workflow: 1, Tag: "evidence", Summary: "Export evidence as Nmap XML"},
	{Method: "GET",    Path: "/api/evidence/{job_id}/jsonl", Workflow: 1, Tag: "evidence", Summary: "Export evidence as JSONL"},
	{Method: "POST",   Path: "/api/probe",                Workflow: 1, Tag: "probe",    Summary: "Run an ad-hoc probe"},
	{Method: "GET",    Path: "/api/presets",              Workflow: 1, Tag: "scan",     Summary: "List scan presets"},

	// ─── W2: Proxy & Tunnel ────────────────────────────────────────────────
	{Method: "GET",    Path: "/api/subscriptions",              Workflow: 2, Tag: "subscription", Summary: "List subscriptions"},
	{Method: "POST",   Path: "/api/subscriptions",             Workflow: 2, Tag: "subscription", Summary: "Add subscription"},
	{Method: "DELETE", Path: "/api/subscriptions/{id}",        Workflow: 2, Tag: "subscription", Summary: "Remove subscription"},
	{Method: "POST",   Path: "/api/subscriptions/{id}/refresh",Workflow: 2, Tag: "subscription", Summary: "Force refresh subscription"},
	{Method: "GET",    Path: "/api/proxies",                   Workflow: 2, Tag: "proxy",        Summary: "List available proxies"},
	{Method: "POST",   Path: "/api/proxies/parse",             Workflow: 2, Tag: "proxy",        Summary: "Parse proxy URI(s)"},
	{Method: "POST",   Path: "/api/proxies/test",              Workflow: 2, Tag: "proxy",        Summary: "Test a proxy connection"},
	{Method: "GET",    Path: "/api/proxies/directory",         Workflow: 2, Tag: "proxy",        Summary: "Proxy directory / corpus"},
	{Method: "GET",    Path: "/api/routing",                   Workflow: 2, Tag: "routing",      Summary: "Get current routing config"},
	{Method: "POST",   Path: "/api/routing",                   Workflow: 2, Tag: "routing",      Summary: "Update routing config"},
	{Method: "GET",    Path: "/api/routing/plugins",           Workflow: 2, Tag: "routing",      Summary: "List routing plugins"},
	{Method: "POST",   Path: "/api/routing/rules",             Workflow: 2, Tag: "routing",      Summary: "Evaluate a rule set"},
	{Method: "GET",    Path: "/api/evasion",                   Workflow: 2, Tag: "evasion",      Summary: "Get evasion config"},
	{Method: "POST",   Path: "/api/evasion",                   Workflow: 2, Tag: "evasion",      Summary: "Update evasion config"},
	{Method: "POST",   Path: "/api/jobs/dispatch",             Workflow: 2, Tag: "jobs",         Summary: "Dispatch a UI job"},
	{Method: "GET",    Path: "/api/jobs/{job_id}",             Workflow: 2, Tag: "jobs",         Summary: "Get job status"},

	// ─── W3: System & Configuration ────────────────────────────────────────
	{Method: "GET",    Path: "/api/system/status",       Workflow: 3, Tag: "system", Summary: "Get system status"},
	{Method: "POST",   Path: "/api/system/start",        Workflow: 3, Tag: "system", Summary: "Start the proxy engine"},
	{Method: "POST",   Path: "/api/system/stop",         Workflow: 3, Tag: "system", Summary: "Stop the proxy engine"},
	{Method: "GET",    Path: "/api/system/dns",          Workflow: 3, Tag: "dns",    Summary: "Get DNS configuration"},
	{Method: "POST",   Path: "/api/system/dns",          Workflow: 3, Tag: "dns",    Summary: "Update DNS configuration"},
	{Method: "GET",    Path: "/api/system/proxy",        Workflow: 3, Tag: "system", Summary: "Get system proxy settings"},
	{Method: "POST",   Path: "/api/system/proxy",        Workflow: 3, Tag: "system", Summary: "Update system proxy settings"},
	{Method: "GET",    Path: "/api/system/ncsi",         Workflow: 3, Tag: "ncsi",   Summary: "Get NCSI override status"},
	{Method: "POST",   Path: "/api/system/ncsi",         Workflow: 3, Tag: "ncsi",   Summary: "Set NCSI override"},
	{Method: "GET",    Path: "/api/system/tun",          Workflow: 3, Tag: "tun",    Summary: "Get TUN adapter status"},
	{Method: "POST",   Path: "/api/system/tun",          Workflow: 3, Tag: "tun",    Summary: "Configure TUN adapter"},
	{Method: "GET",    Path: "/api/system/engines",      Workflow: 3, Tag: "system", Summary: "List available proxy engines"},
	{Method: "POST",   Path: "/api/system/startup",      Workflow: 3, Tag: "system", Summary: "Configure autostart"},
	{Method: "GET",    Path: "/api/system/ddns",         Workflow: 3, Tag: "ddns",   Summary: "Get DDNS configuration"},
	{Method: "POST",   Path: "/api/system/ddns",         Workflow: 3, Tag: "ddns",   Summary: "Update DDNS configuration"},
	{Method: "GET",    Path: "/api/config",              Workflow: 3, Tag: "config",  Summary: "Get full runtime config"},
	{Method: "POST",   Path: "/api/config",              Workflow: 3, Tag: "config",  Summary: "Update runtime config"},
	{Method: "GET",    Path: "/api/capabilities",        Workflow: 3, Tag: "system",  Summary: "Get platform capabilities"},

	// ─── W4: Covert & Intelligence ─────────────────────────────────────────
	{Method: "POST",   Path: "/api/covert/links",              Workflow: 4, Tag: "covert",   Summary: "Create a covert link"},
	{Method: "GET",    Path: "/api/covert/links",              Workflow: 4, Tag: "covert",   Summary: "List covert links"},
	{Method: "DELETE", Path: "/api/covert/links/{link_id}",    Workflow: 4, Tag: "covert",   Summary: "Delete a covert link"},
	{Method: "GET",    Path: "/api/covert/visits",             Workflow: 4, Tag: "covert",   Summary: "List covert visit records"},
	{Method: "GET",    Path: "/api/covert/visits/live",        Workflow: 4, Tag: "covert",   Summary: "Live visit stream (SSE/WS)"},
	{Method: "GET",    Path: "/api/traffic",                   Workflow: 4, Tag: "traffic",  Summary: "Get per-app traffic stats"},
	{Method: "GET",    Path: "/api/safety-policy",             Workflow: 4, Tag: "safety",   Summary: "Get safety policy"},
	{Method: "POST",   Path: "/api/safety-policy",             Workflow: 4, Tag: "safety",   Summary: "Update safety policy"},
	{Method: "GET",    Path: "/api/history",                   Workflow: 4, Tag: "history",  Summary: "Get connection history"},

	// ─── W5: Observability ─────────────────────────────────────────────────
	{Method: "GET", Path: "/api/metrics",       Workflow: 5, Tag: "observability", Summary: "Prometheus-format metrics"},
	{Method: "GET", Path: "/api/doctor",        Workflow: 5, Tag: "observability", Summary: "Readiness/health check"},
	{Method: "GET", Path: "/api/diagnostics",   Workflow: 5, Tag: "observability", Summary: "Diagnostic report"},
	{Method: "GET", Path: "/api/events",        Workflow: 5, Tag: "observability", Summary: "WebSocket event stream"},
	{Method: "POST", Path: "/api/session/ws",   Workflow: 5, Tag: "observability", Summary: "Issue a short-lived WebSocket session"},
	{Method: "GET", Path: "/api/routes",        Workflow: 5, Tag: "observability", Summary: "List registered API routes", Public: true},
	{Method: "GET", Path: "/api/version",       Workflow: 5, Tag: "observability", Summary: "Version information", Public: true},
	{Method: "GET", Path: "/api/speedtest",     Workflow: 5, Tag: "observability", Summary: "Run speed test"},
}

// RoutesByWorkflow returns routes grouped by workflow number (1–5).
func RoutesByWorkflow() map[int][]RouteSpec {
	out := make(map[int][]RouteSpec)
	for _, r := range Routes {
		out[r.Workflow] = append(out[r.Workflow], r)
	}
	return out
}

// RoutesByTag returns routes grouped by tag.
func RoutesByTag() map[string][]RouteSpec {
	out := make(map[string][]RouteSpec)
	for _, r := range Routes {
		out[r.Tag] = append(out[r.Tag], r)
	}
	return out
}
