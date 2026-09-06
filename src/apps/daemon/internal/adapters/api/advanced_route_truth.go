package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type advancedRouteMode string

const (
	advancedRouteAnalysis    advancedRouteMode = "analysis"
	advancedRouteOperational advancedRouteMode = "operational"
	advancedRouteUnavailable advancedRouteMode = "unavailable"
)

type advancedRouteTruth struct {
	Mode   advancedRouteMode
	Reason string
}

// advancedSystemRouteTruth records capability truth for every route in the
// legacy advanced /api/system cluster. Registration remains the source of
// route existence; Wave 20 consumes this metadata from the same route owner.
var advancedSystemRouteTruth = map[string]advancedRouteTruth{
	"POST /sni-spoofing":       {Mode: advancedRouteUnavailable, Reason: "no active runtime consumes this legacy injector configuration; use the evasion-tunnel runtime for supported SNI behavior"},
	"POST /dpi-desync":         {Mode: advancedRouteUnavailable, Reason: "no active runtime consumes this legacy desync engine; use the evasion-tunnel runtime for supported packet-splitting behavior"},
	"POST /cdn-discover":       {Mode: advancedRouteAnalysis, Reason: "request-scoped clean-IP discovery; no persistent runtime state is mutated"},
	"POST /cloudflare-deploy":  {Mode: advancedRouteOperational, Reason: "request-scoped Cloudflare Worker deployment"},
	"POST /gdrive-tunnel":      {Mode: advancedRouteUnavailable, Reason: "legacy relay only encoded payloads locally and never used folder_id or access_token; no Google Drive transport is active"},
	"GET /master-telemetry":    {Mode: advancedRouteUnavailable, Reason: "legacy orchestrator telemetry loop is not part of the active daemon runtime"},
	"POST /subscription-parse": {Mode: advancedRouteAnalysis, Reason: "compatibility parser; Wave 19 moves parsing behind the subscription owner"},
	"GET /vpn-state":           {Mode: advancedRouteUnavailable, Reason: "no active VPN owner publishes state to this legacy bridge"},
	"POST /doh-blocklist":      {Mode: advancedRouteAnalysis, Reason: "request-scoped static blocklist evaluation"},
	"POST /antibot-inspect":    {Mode: advancedRouteAnalysis, Reason: "pure response-signature analysis"},
	"POST /warp-noise":         {Mode: advancedRouteOperational, Reason: "request-scoped WARP noise packet injection"},
	"POST /warp-register":      {Mode: advancedRouteOperational, Reason: "request-scoped Cloudflare WARP registration"},
	"POST /warp-scan":          {Mode: advancedRouteOperational, Reason: "request-scoped WARP endpoint scan"},
	"POST /geosite-match":      {Mode: advancedRouteAnalysis, Reason: "embedded domain-corpus classification"},
	"GET /device-profile":      {Mode: advancedRouteUnavailable, Reason: "device-profile emulation is not connected to an active transport runtime"},
	"POST /device-profile":     {Mode: advancedRouteUnavailable, Reason: "device-profile emulation is not connected to an active transport runtime"},
	"POST /smart-dns":          {Mode: advancedRouteAnalysis, Reason: "request-scoped DNS lookup"},
	"POST /cdn-fronting":       {Mode: advancedRouteAnalysis, Reason: "dial-override construction only; no persistent runtime state is mutated"},
	"POST /clean-ip-probe":     {Mode: advancedRouteAnalysis, Reason: "request-scoped clean-IP probe"},
	"POST /ip-security":        {Mode: advancedRouteAnalysis, Reason: "pure IP metadata classification"},
}

func unavailableAdvancedCapability(c *gin.Context, routeKey string) {
	truth, ok := advancedSystemRouteTruth[routeKey]
	if !ok || truth.Mode != advancedRouteUnavailable {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status": "error",
			"reason": "advanced route truth metadata is missing or inconsistent",
		})
		return
	}
	c.JSON(http.StatusNotImplemented, gin.H{
		"status":     "unavailable",
		"capability": routeKey,
		"reason":     truth.Reason,
	})
}
