package api

import (
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

// LiveRoute describes an endpoint that is actually registered in Gin.
type LiveRoute struct {
	Method       string `json:"method"`
	Path         string `json:"path"`
	Workflow     int    `json:"workflow"`
	Tag          string `json:"tag"`
	Public       bool   `json:"public"`
	Capability   string `json:"capability,omitempty"`
	Availability string `json:"availability"`
	Deprecated   bool   `json:"deprecated"`
}

func (s *Server) setupRouteIntrospection(r *gin.Engine) {
	r.GET("/api/routes", func(c *gin.Context) {
		routes := make([]LiveRoute, 0, len(r.Routes()))
		for _, route := range r.Routes() {
			classification := classifyRoute(route.Path)
			capability, availability, deprecated := routeRuntimeMetadata(route.Method, route.Path)
			routes = append(routes, LiveRoute{
				Method:       route.Method,
				Path:         route.Path,
				Workflow:     classification.Workflow,
				Tag:          classification.Tag,
				Public:       isPublicRoute(route.Method, route.Path),
				Capability:   capability,
				Availability: availability,
				Deprecated:   deprecated,
			})
		}
		sort.Slice(routes, func(i, j int) bool {
			if routes[i].Path == routes[j].Path {
				return routes[i].Method < routes[j].Method
			}
			return routes[i].Path < routes[j].Path
		})
		c.JSON(http.StatusOK, routes)
	})
}

func isPublicRoute(method, path string) bool {
	if method != http.MethodGet {
		return false
	}
	switch path {
	case "/health", "/api/version", "/api/routes", "/ws":
		return true
	default:
		return false
	}
}

func routeRuntimeMetadata(method, path string) (capability, availability string, deprecated bool) {
	availability = "available"
	if len(path) > len("/api/system") && path[:len("/api/system")] == "/api/system" {
		key := method + " " + path[len("/api/system"):]
		if truth, ok := advancedSystemRouteTruth[key]; ok {
			return "advanced-system", string(truth.Mode), false
		}
	}
	switch {
	case path == "/api/system/dns":
		capability = "dns-control"
	case path == "/api/system/proxy", path == "/api/system/evasion-tunnel", path == "/api/system/engines":
		capability = "proxy-control"
	case path == "/api/system/flows" || strings.HasPrefix(path, "/api/system/flows/"):
		capability = "flow-observability"
	case path == "/api/system/network-state":
		capability = "network-state"
	case path == "/api/diagnostics" || len(path) > len("/api/diagnostics/") && path[:len("/api/diagnostics/")] == "/api/diagnostics/":
		capability = "diagnostics"
	}
	return capability, availability, false
}

type routeClassification struct {
	Workflow int
	Tag      string
}

func classifyRoute(path string) routeClassification {
	path = strings.ToLower(path)
	switch {
	case hasAnyRoutePrefix(path,
		"/api/scan", "/api/scan-results", "/api/dns-scan", "/api/tls-scan",
		"/api/sni-scan", "/api/probe", "/api/presets", "/api/provider-corpus"):
		return routeClassification{Workflow: 1, Tag: "scan"}
	case hasAnyRoutePrefix(path,
		"/api/proxy", "/api/proxies", "/api/subscriptions", "/api/routing",
		"/api/evasion", "/api/fptn", "/api/jobs"):
		return routeClassification{Workflow: 2, Tag: "proxy"}
	case hasAnyRoutePrefix(path,
		"/api/system", "/api/config", "/api/capabilities", "/api/server-config"):
		return routeClassification{Workflow: 3, Tag: "system"}
	case hasAnyRoutePrefix(path,
		"/api/covert", "/api/telegram", "/api/traffic", "/api/history", "/api/export"):
		return routeClassification{Workflow: 4, Tag: "intelligence"}
	default:
		return routeClassification{Workflow: 5, Tag: "observability"}
	}
}

func hasAnyRoutePrefix(path string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
