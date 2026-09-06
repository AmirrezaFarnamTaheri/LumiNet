package routing

import (
	"sync"
)

type GeoPoint struct {
	Latitude  float64
	Longitude float64
}

type GeoBoundingBox struct {
	MinLat float64
	MaxLat float64
	MinLon float64
	MaxLon float64
}

func (b *GeoBoundingBox) Contains(p GeoPoint) bool {
	return p.Latitude >= b.MinLat && p.Latitude <= b.MaxLat &&
		p.Longitude >= b.MinLon && p.Longitude <= b.MaxLon
}

type GeoFencedRegion struct {
	RegionCode string
	RegionName string
	Vertices   []GeoPoint
	BBox       GeoBoundingBox
	EgressTag  string
}

func NewGeoFencedRegion(code, name string, vertices []GeoPoint, egressTag string) *GeoFencedRegion {
	minLat, minLon := 1e9, 1e9
	maxLat, maxLon := -1e9, -1e9

	for _, v := range vertices {
		if v.Latitude < minLat {
			minLat = v.Latitude
		}
		if v.Latitude > maxLat {
			maxLat = v.Latitude
		}
		if v.Longitude < minLon {
			minLon = v.Longitude
		}
		if v.Longitude > maxLon {
			maxLon = v.Longitude
		}
	}

	return &GeoFencedRegion{
		RegionCode: code,
		RegionName: name,
		Vertices:   vertices,
		BBox: GeoBoundingBox{
			MinLat: minLat,
			MaxLat: maxLat,
			MinLon: minLon,
			MaxLon: maxLon,
		},
		EgressTag: egressTag,
	}
}

func (r *GeoFencedRegion) ContainsPoint(p GeoPoint) bool {
	if !r.BBox.Contains(p) {
		return false
	}

	n := len(r.Vertices)
	if n < 3 {
		return false
	}

	inside := false
	j := n - 1
	for i := 0; i < n; i++ {
		vi := r.Vertices[i]
		vj := r.Vertices[j]

		intersect := ((vi.Latitude > p.Latitude) != (vj.Latitude > p.Latitude)) &&
			(p.Longitude < (vj.Longitude-vi.Longitude)*(p.Latitude-vi.Latitude)/(vj.Latitude-vi.Latitude)+vi.Longitude)

		if intersect {
			inside = !inside
		}
		j = i
	}
	return inside
}

type GeospatialPolygonRouter struct {
	regions       []*GeoFencedRegion
	defaultEgress string
	mu            sync.RWMutex
}

func NewGeospatialPolygonRouter(defaultEgress string) *GeospatialPolygonRouter {
	return &GeospatialPolygonRouter{
		defaultEgress: defaultEgress,
	}
}

func (g *GeospatialPolygonRouter) AddRegion(region *GeoFencedRegion) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.regions = append(g.regions, region)
}

func (g *GeospatialPolygonRouter) ResolveEgress(p GeoPoint) (string, string) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	for _, r := range g.regions {
		if r.ContainsPoint(p) {
			return r.EgressTag, r.RegionCode
		}
	}
	return g.defaultEgress, ""
}
