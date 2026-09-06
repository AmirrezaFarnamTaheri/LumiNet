package api

import "testing"

func TestClassifyRouteWorkflowFamilies(t *testing.T) {
	t.Parallel()
	cases := map[string]routeClassification{
		"/api/scan/start":              {Workflow: 1, Tag: "scan"},
		"/api/presets/cdn":             {Workflow: 1, Tag: "scan"},
		"/api/proxies/test":            {Workflow: 2, Tag: "proxy"},
		"/api/subscriptions/aggregate": {Workflow: 2, Tag: "proxy"},
		"/api/system/tun":              {Workflow: 3, Tag: "system"},
		"/api/server-config":           {Workflow: 3, Tag: "system"},
		"/api/telegram/mtproto":        {Workflow: 4, Tag: "intelligence"},
		"/api/history":                 {Workflow: 4, Tag: "intelligence"},
		"/api/diagnostics":             {Workflow: 5, Tag: "observability"},
		"/api/routes":                  {Workflow: 5, Tag: "observability"},
		"/health":                      {Workflow: 5, Tag: "observability"},
	}
	for path, want := range cases {
		if got := classifyRoute(path); got != want {
			t.Errorf("classifyRoute(%q) = %#v, want %#v", path, got, want)
		}
	}
}
