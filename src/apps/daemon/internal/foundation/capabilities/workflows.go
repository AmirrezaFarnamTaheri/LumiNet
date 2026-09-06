package capabilities

import (
	"fmt"
	"strings"
)

type WorkflowID string

const (
	WorkflowDiagnoseNetwork WorkflowID = "Diagnose Network"
	WorkflowScanTargets     WorkflowID = "Scan Targets"
	WorkflowEvaluateProxies WorkflowID = "Evaluate Proxies"
	WorkflowControlSystem   WorkflowID = "Control System"
	WorkflowOperateLumiNet  WorkflowID = "Operate LumiNet"
)

// GetWorkflowForRoute maps any HTTP API route to one of the 5 canonical workflows.
func GetWorkflowForRoute(method, path string) (WorkflowID, error) {
	cleanPath := strings.TrimSuffix(path, "/")
	if cleanPath == "" {
		cleanPath = "/"
	}

	// Non-API base routes
	if cleanPath == "/health" || cleanPath == "/diagnostics/prober" {
		return WorkflowDiagnoseNetwork, nil
	}
	if cleanPath == "/metrics" {
		return WorkflowOperateLumiNet, nil
	}
	if cleanPath == "/ws" || cleanPath == "/track" || strings.HasPrefix(cleanPath, "/track/") {
		return WorkflowOperateLumiNet, nil
	}

	// API route prefix checks
	if strings.HasPrefix(cleanPath, "/api/") {
		apiSub := strings.TrimPrefix(cleanPath, "/api/")
		apiParts := strings.Split(apiSub, "/")
		if len(apiParts) == 0 || apiParts[0] == "" {
			return "", fmt.Errorf("empty API endpoint: %s", path)
		}

		switch apiParts[0] {
		case "dns-scans", "tls-scans", "sni-scans", "diagnostics", "speedtest", "port-scans", "doctor":
			return WorkflowDiagnoseNetwork, nil
		case "scans", "proxy-scans", "scan-results":
			return WorkflowScanTargets, nil
		case "proxy-tests", "subscriptions", "presets", "provider-corpus", "proxies", "providers", "circumvention":
			return WorkflowEvaluateProxies, nil
		case "system", "capabilities", "config", "server-config":
			return WorkflowControlSystem, nil
		case "history", "telegram", "routing-plugins", "jobs", "export", "fptn", "session", "metrics", "routes", "version":
			return WorkflowOperateLumiNet, nil
		default:
			return "", fmt.Errorf("unregistered workflow prefix for API route: %s (endpoint: %s)", path, apiParts[0])
		}
	}

	return "", fmt.Errorf("route does not map to any workflow: %s", path)
}
