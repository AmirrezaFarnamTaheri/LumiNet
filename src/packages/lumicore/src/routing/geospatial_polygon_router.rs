//! Geospatial Polygon and Geo-Fencing Routing Engine
//!
//! Evaluates geographic coordinates (latitude, longitude) against defined polygonal
//! regional boundaries using ray-casting point-in-polygon tests and bounding-box optimization.

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GeoPoint {
    pub latitude: f64,
    pub longitude: f64,
}

#[derive(Debug, Clone)]
pub struct GeoBoundingBox {
    pub min_lat: f64,
    pub max_lat: f64,
    pub min_lon: f64,
    pub max_lon: f64,
}

impl GeoBoundingBox {
    pub fn contains(&self, p: &GeoPoint) -> bool {
        p.latitude >= self.min_lat
            && p.latitude <= self.max_lat
            && p.longitude >= self.min_lon
            && p.longitude <= self.max_lon
    }
}

#[derive(Debug, Clone)]
pub struct GeoFencedRegion {
    pub region_code: String,
    pub region_name: String,
    pub vertices: Vec<GeoPoint>,
    pub bbox: GeoBoundingBox,
    pub egress_tag: String,
}

impl GeoFencedRegion {
    pub fn new(code: impl Into<String>, name: impl Into<String>, vertices: Vec<GeoPoint>, egress_tag: impl Into<String>) -> Self {
        let mut min_lat = f64::MAX;
        let mut max_lat = f64::MIN;
        let mut min_lon = f64::MAX;
        let mut max_lon = f64::MIN;

        for v in &vertices {
            min_lat = min_lat.min(v.latitude);
            max_lat = max_lat.max(v.latitude);
            min_lon = min_lon.min(v.longitude);
            max_lon = max_lon.max(v.longitude);
        }

        Self {
            region_code: code.into(),
            region_name: name.into(),
            bbox: GeoBoundingBox {
                min_lat,
                max_lat,
                min_lon,
                max_lon,
            },
            vertices,
            egress_tag: egress_tag.into(),
        }
    }

    /// Jordan curve theorem / ray-casting algorithm for point-in-polygon
    pub fn contains_point(&self, p: &GeoPoint) -> bool {
        // Fast bbox rejection
        if !self.bbox.contains(p) {
            return false;
        }

        let n = self.vertices.len();
        if n < 3 {
            return false;
        }

        let mut inside = false;
        let mut j = n - 1;

        for i in 0..n {
            let vi = &self.vertices[i];
            let vj = &self.vertices[j];

            let intersect = ((vi.latitude > p.latitude) != (vj.latitude > p.latitude))
                && (p.longitude < (vj.longitude - vi.longitude) * (p.latitude - vi.latitude) / (vj.latitude - vi.latitude) + vi.longitude);

            if intersect {
                inside = !inside;
            }
            j = i;
        }

        inside
    }
}

pub struct GeospatialPolygonRouter {
    regions: Vec<GeoFencedRegion>,
    default_egress_tag: String,
}

impl GeospatialPolygonRouter {
    pub fn new(default_egress: impl Into<String>) -> Self {
        Self {
            regions: Vec::new(),
            default_egress_tag: default_egress.into(),
        }
    }

    pub fn add_region(&mut self, region: GeoFencedRegion) {
        self.regions.push(region);
    }

    pub fn resolve_egress_for_coordinates(&self, point: &GeoPoint) -> (String, Option<String>) {
        for r in &self.regions {
            if r.contains_point(point) {
                return (r.egress_tag.clone(), Some(r.region_code.clone()));
            }
        }
        (self.default_egress_tag.clone(), None)
    }

    pub fn total_regions(&self) -> usize {
        self.regions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geospatial_polygon_containment() {
        let mut router = GeospatialPolygonRouter::new("direct-egress");

        // Define a simple triangular polygon region around Tokyo
        let tokyo_poly = vec![
            GeoPoint { latitude: 35.5, longitude: 139.5 },
            GeoPoint { latitude: 35.8, longitude: 139.9 },
            GeoPoint { latitude: 35.4, longitude: 139.9 },
        ];

        let region = GeoFencedRegion::new("JP-TYO", "Tokyo Metro", tokyo_poly, "proxy-jp-node");
        router.add_region(region);

        let inside_point = GeoPoint { latitude: 35.6, longitude: 139.8 };
        let outside_point = GeoPoint { latitude: 34.0, longitude: 135.0 };

        let (tag1, code1) = router.resolve_egress_for_coordinates(&inside_point);
        assert_eq!(tag1, "proxy-jp-node");
        assert_eq!(code1, Some("JP-TYO".to_string()));

        let (tag2, code2) = router.resolve_egress_for_coordinates(&outside_point);
        assert_eq!(tag2, "direct-egress");
        assert_eq!(code2, None);
    }
}
