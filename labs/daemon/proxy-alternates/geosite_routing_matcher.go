package proxy

import "github.com/maybeknott/luminet/internal/domainrouting"

// GeoSiteMatcher remains available from proxy for compatibility. Mutable
// domain override ownership now lives in internal/domainrouting.
type GeoSiteMatcher = domainrouting.DynamicMatcher

// NewGeoSiteMatcher preserves the historical constructor while delegating to
// the canonical domain-routing owner.
func NewGeoSiteMatcher() *GeoSiteMatcher { return domainrouting.NewDynamicMatcher() }
