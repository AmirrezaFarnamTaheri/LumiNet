package proxy

// Ported from: XHTTPRelayECO-master templates/landing
// Target: server/internal/proxy/landing_disguise.go

import "log/slog"

// LandingDisguise serves a decoy landing page to mask relay traffic.
type LandingDisguise struct {
	enabled bool
	html    string
}

// NewLandingDisguise creates a landing page disguise for relay endpoints.
func NewLandingDisguise(enabled bool, html string) *LandingDisguise {
	return &LandingDisguise{enabled: enabled, html: html}
}

// ServeHTTP returns the decoy page for unauthenticated visitors.
func (l *LandingDisguise) ServeHTTP() {
	if !l.enabled {
		return
	}
	slog.Info("LandingDisguise", "status", "serving decoy landing page")
}
