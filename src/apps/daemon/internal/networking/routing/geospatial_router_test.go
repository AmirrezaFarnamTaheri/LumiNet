package routing

import (
	"testing"
)

func TestGeospatialPolygonRouter(t *testing.T) {
	router := NewGeospatialPolygonRouter("direct")

	// Triangle around Tokyo
	tokyoPoly := []GeoPoint{
		{Latitude: 35.5, Longitude: 139.5},
		{Latitude: 35.8, Longitude: 139.9},
		{Latitude: 35.4, Longitude: 139.9},
	}
	region := NewGeoFencedRegion("JP-TYO", "Tokyo Metro", tokyoPoly, "jp-proxy")
	router.AddRegion(region)

	inside := GeoPoint{Latitude: 35.6, Longitude: 139.8}
	outside := GeoPoint{Latitude: 40.0, Longitude: 140.0}

	tag, code := router.ResolveEgress(inside)
	if tag != "jp-proxy" || code != "JP-TYO" {
		t.Fatalf("expected inside to match jp-proxy, got tag=%s code=%s", tag, code)
	}

	tag, code = router.ResolveEgress(outside)
	if tag != "direct" || code != "" {
		t.Fatalf("expected outside to be direct, got tag=%s code=%s", tag, code)
	}
}
