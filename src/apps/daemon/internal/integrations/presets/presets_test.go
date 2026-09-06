package presets

import "testing"

func TestCatalogCounts(t *testing.T) {
	checks := []struct {
		name      string
		got, want int
	}{
		{"cdn", len(GetCDNPresets()), 16},
		{"warp ports", len(GetWarpPorts()), 54},
		{"doh", len(GetDoHPresets()), 31},
		{"dns", len(GetDNSPresets()), 53},
		{"scan", len(GetScanPresets()), 5},
		{"isp", len(GetEvasionISPPresets()), 4},
		{"serverless", len(GetServerlessRoutingPresets()), 2},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Fatalf("%s count=%d want=%d", check.name, check.got, check.want)
		}
	}
}

func TestCatalogResultsAreFreshValues(t *testing.T) {
	ports := GetWarpPorts()
	ports[0] = -1
	if GetWarpPorts()[0] == -1 {
		t.Fatal("warp port result aliases mutable backing storage")
	}
	cdn := GetCDNPresets()
	cdn[0].Ranges[0].Cidr = "mutated"
	if GetCDNPresets()[0].Ranges[0].Cidr == "mutated" {
		t.Fatal("CDN result aliases mutable backing storage")
	}
}

func TestPostRefactor224Quad9DoHVariantsRemainDistinct(t *testing.T) {
	seen := map[string]string{}
	for _, p := range GetDoHPresets() {
		seen[p.ID] = p.URL
	}
	for _, id := range []string{"quad9-secured", "quad9-unsecured", "quad9-secured-ecs"} {
		if seen[id] == "" {
			t.Fatalf("missing %s", id)
		}
	}
	if seen["quad9-secured"] == seen["quad9-unsecured"] || seen["quad9-secured"] == seen["quad9-secured-ecs"] || seen["quad9-unsecured"] == seen["quad9-secured-ecs"] {
		t.Fatalf("variants collapsed: %+v", seen)
	}
}
