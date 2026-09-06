package proxyconfig

import (
	"sort"
	"testing"
)

func TestConfigRegistry_RegisterAndGet(t *testing.T) {
	r := NewConfigRegistry()
	err := r.Register(&DialerNode{
		Name:      "direct",
		Transport: "direct",
		URI:       "direct://",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	got := r.Get("direct")
	if got == nil {
		t.Fatal("Get returned nil")
	}
	if got.Transport != "direct" {
		t.Errorf("Transport: got %q, want %q", got.Transport, "direct")
	}
}

func TestConfigRegistry_RegisterRejectsInvalid(t *testing.T) {
	r := NewConfigRegistry()
	tests := []struct {
		name string
		node *DialerNode
	}{
		{"nil node", nil},
		{"empty name", &DialerNode{Transport: "direct", URI: "direct://"}},
		{"empty transport", &DialerNode{Name: "a", URI: "direct://"}},
		{"empty uri", &DialerNode{Name: "a", Transport: "direct"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := r.Register(tc.node); err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestConfigRegistry_RemoveBlocksDependents(t *testing.T) {
	r := NewConfigRegistry()
	must := func(n *DialerNode) {
		if err := r.Register(n); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	must(&DialerNode{Name: "direct", Transport: "direct", URI: "direct://"})
	must(&DialerNode{Name: "socks", Transport: "socks5", URI: "socks5://127.0.0.1:1080", DependsOn: []string{"direct"}})

	if err := r.Remove("direct"); err == nil {
		t.Error("expected error removing depended-on node")
	}
	if err := r.Remove("socks"); err != nil {
		t.Errorf("Remove socks: %v", err)
	}
	if r.Get("socks") != nil {
		t.Error("socks should be gone")
	}
	if err := r.Remove("direct"); err != nil {
		t.Errorf("Remove direct after dependents cleared: %v", err)
	}
}

func TestConfigRegistry_ListSorted(t *testing.T) {
	r := NewConfigRegistry()
	for _, name := range []string{"c", "a", "b"} {
		if err := r.Register(&DialerNode{Name: name, Transport: "direct", URI: "direct://"}); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	names := r.List()
	expected := []string{"a", "b", "c"}
	if !equalSlices(names, expected) {
		t.Errorf("List: got %v, want %v", names, expected)
	}
}

func TestConfigRegistry_BuildGraph_Topological(t *testing.T) {
	r := NewConfigRegistry()
	must := func(n *DialerNode) {
		if err := r.Register(n); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	must(&DialerNode{Name: "direct", Transport: "direct", URI: "direct://"})
	must(&DialerNode{Name: "ss-local", Transport: "shadowsocks", URI: "ss://...", DependsOn: []string{"direct"}})
	must(&DialerNode{Name: "socks", Transport: "socks5", URI: "socks5://...", DependsOn: []string{"direct"}})
	must(&DialerNode{Name: "http", Transport: "http", URI: "http://...", DependsOn: []string{"socks"}})

	g, err := r.BuildGraph()
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}
	if len(g.Ordered) != 4 {
		t.Fatalf("expected 4 nodes, got %d: %v", len(g.Ordered), g.Ordered)
	}
	// "direct" must come first (no dependencies).
	if g.Ordered[0] != "direct" {
		t.Errorf("first node should be direct, got %q", g.Ordered[0])
	}
	// "http" must come last (depends on socks, which depends on direct).
	if g.Ordered[3] != "http" {
		t.Errorf("last node should be http, got %q", g.Ordered[3])
	}
}

func TestConfigRegistry_BuildGraph_Cycle(t *testing.T) {
	r := NewConfigRegistry()
	must := func(n *DialerNode) {
		if err := r.Register(n); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	must(&DialerNode{Name: "a", Transport: "direct", URI: "direct://", DependsOn: []string{"b"}})
	must(&DialerNode{Name: "b", Transport: "direct", URI: "direct://", DependsOn: []string{"a"}})

	_, err := r.BuildGraph()
	if err == nil {
		t.Fatal("expected cycle error")
	}
	ge, ok := err.(*GraphError)
	if !ok {
		t.Fatalf("expected *GraphError, got %T", err)
	}
	found := false
	for _, e := range ge.Errors {
		if e == "cycle detected in dialer graph" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected cycle error in %v", ge.Errors)
	}
}

func TestConfigRegistry_BuildGraph_MissingDep(t *testing.T) {
	r := NewConfigRegistry()
	if err := r.Register(&DialerNode{
		Name:      "ss",
		Transport: "shadowsocks",
		URI:       "ss://...",
		DependsOn: []string{"nonexistent"},
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	_, err := r.BuildGraph()
	if err == nil {
		t.Fatal("expected missing dep error")
	}
}

func TestConfigRegistry_EntryPointByWeight(t *testing.T) {
	r := NewConfigRegistry()
	must := func(n *DialerNode) {
		if err := r.Register(n); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	must(&DialerNode{Name: "a", Transport: "direct", URI: "direct://", Weight: 1})
	must(&DialerNode{Name: "b", Transport: "direct", URI: "direct://", Weight: 10})

	g, err := r.BuildGraph()
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}
	if g.EntryPoint != "b" {
		t.Errorf("expected entry point b, got %q", g.EntryPoint)
	}
}

func TestConfigRegistry_Alias(t *testing.T) {
	r := NewConfigRegistry()
	if err := r.Register(&DialerNode{
		Name:      "primary",
		Transport: "direct",
		URI:       "direct://",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := r.AddAlias("default", "primary"); err != nil {
		t.Fatalf("AddAlias: %v", err)
	}
	got := r.Get("default")
	if got == nil {
		t.Fatal("alias resolution failed")
	}
	if got.Name != "primary" {
		t.Errorf("expected primary, got %q", got.Name)
	}
}

func TestConfigRegistry_Clear(t *testing.T) {
	r := NewConfigRegistry()
	if err := r.Register(&DialerNode{Name: "a", Transport: "direct", URI: "direct://"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	r.Clear()
	if r.Size() != 0 {
		t.Errorf("expected size 0 after clear, got %d", r.Size())
	}
}

func TestConfigRegistry_GetReturnsCopy(t *testing.T) {
	r := NewConfigRegistry()
	if err := r.Register(&DialerNode{
		Name:      "a",
		Transport: "direct",
		URI:       "direct://",
		Metadata:  map[string]string{"k": "v"},
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got := r.Get("a")
	got.Metadata["k"] = "mutated"
	got2 := r.Get("a")
	if got2.Metadata["k"] != "v" {
		t.Error("Get should return a deep copy of metadata")
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Ensure sort import is used to avoid "imported and not used" if all tests
// above don't reference it indirectly.
var _ = sort.Strings
