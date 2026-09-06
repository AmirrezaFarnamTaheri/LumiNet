package sub

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

func testSubscriptionNode(name, address, credential string) *proxyconfig.ProxyConfig {
	return &proxyconfig.ProxyConfig{
		Protocol:  proxyconfig.ProtocolVLESS,
		Name:      name,
		Address:   address,
		Port:      443,
		UUID:      credential,
		TLS:       true,
		SNI:       "edge.example",
		Transport: "ws",
		Path:      "/ws",
		RawURI:    "vless://" + credential + "@" + address + ":443?security=tls#" + name,
	}
}

func TestNodeCatalogueRedactsSecretsAndResolvesOnlyVisibleNodes(t *testing.T) {
	c, err := NewNodeCatalogue()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Replace("p1", []*proxyconfig.ProxyConfig{
		testSubscriptionNode("alpha", "one.example", "secret-alpha"),
		testSubscriptionNode("beta", "two.example", "secret-beta"),
	}); err != nil {
		t.Fatal(err)
	}

	views := c.List("p1", false)
	if len(views) != 2 {
		t.Fatalf("views=%d", len(views))
	}
	encoded, _ := json.Marshal(views)
	text := string(encoded)
	for _, secret := range []string{"secret-alpha", "secret-beta", "vless://"} {
		if strings.Contains(text, secret) {
			t.Fatalf("view leaked %q: %s", secret, text)
		}
	}

	if err := c.SetHidden("p1", []string{views[0].ID}, true); err != nil {
		t.Fatal(err)
	}
	if got := c.List("p1", false); len(got) != 1 {
		t.Fatalf("visible=%d", len(got))
	}
	if _, err := c.Resolve("p1", views[0].ID); err == nil {
		t.Fatal("hidden node resolved")
	}
	resolved, err := c.Resolve("p1", views[1].ID)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.UUID != "secret-beta" {
		t.Fatal("internal credential was not preserved")
	}
	resolved.UUID = "mutated"
	resolved2, _ := c.Resolve("p1", views[1].ID)
	if resolved2.UUID != "secret-beta" {
		t.Fatal("Resolve returned internal mutable pointer")
	}
}

func TestNodeCatalogueRejectsHideAllAtomicallyAndUnknownIDs(t *testing.T) {
	c, _ := NewNodeCatalogue()
	_ = c.Replace("p1", []*proxyconfig.ProxyConfig{
		testSubscriptionNode("alpha", "one.example", "a"),
		testSubscriptionNode("beta", "two.example", "b"),
	})
	views := c.List("p1", false)
	if err := c.SetHidden("p1", []string{views[0].ID, views[1].ID}, true); err == nil {
		t.Fatal("hide-all accepted")
	}
	if got := c.List("p1", false); len(got) != 2 {
		t.Fatalf("failed mutation changed catalogue: %d", len(got))
	}
	if err := c.SetHidden("p1", []string{"unknown"}, true); err == nil {
		t.Fatal("unknown id accepted")
	}
}

func TestNodeCatalogueRefreshPreservesOwnershipAcrossCredentialRotation(t *testing.T) {
	c, _ := NewNodeCatalogue()
	_ = c.Replace("p1", []*proxyconfig.ProxyConfig{testSubscriptionNode("alpha", "one.example", "old-secret")})
	before := c.List("p1", true)[0]
	if err := c.SetHidden("p1", []string{before.ID}, true); err == nil {
		t.Fatal("single node may not be hidden")
	}
	_ = c.Replace("p1", []*proxyconfig.ProxyConfig{
		testSubscriptionNode("alpha", "one.example", "old-secret"),
		testSubscriptionNode("beta", "two.example", "b"),
	})
	before = c.List("p1", true)[0]
	if err := c.SetHidden("p1", []string{before.ID}, true); err != nil {
		t.Fatal(err)
	}

	_ = c.Replace("p1", []*proxyconfig.ProxyConfig{
		testSubscriptionNode("alpha", "one.example", "rotated-secret"),
		testSubscriptionNode("beta", "two.example", "b"),
	})
	all := c.List("p1", true)
	var alpha MaterializedNodeView
	for _, v := range all {
		if v.Name == "alpha" {
			alpha = v
		}
	}
	if alpha.ID != before.ID {
		t.Fatalf("ownership id changed across credential rotation: %q != %q", alpha.ID, before.ID)
	}
	if !alpha.Hidden {
		t.Fatal("hidden overlay did not survive credential rotation")
	}
	if _, err := c.Resolve("p1", alpha.ID); err == nil {
		t.Fatal("hidden rotated node resolved")
	}
}

func TestNodeCatalogueClearRemovesSourceAuthority(t *testing.T) {
	c, _ := NewNodeCatalogue()
	_ = c.Replace("p1", []*proxyconfig.ProxyConfig{testSubscriptionNode("alpha", "one.example", "a")})
	id := c.List("p1", true)[0].ID
	c.Clear("p1")
	if len(c.List("p1", true)) != 0 {
		t.Fatal("clear retained views")
	}
	if _, err := c.Resolve("p1", id); err == nil {
		t.Fatal("cleared node still resolves")
	}
}

func TestPostRefactor228NodeViewExposesRuntimeCompatibilityWithoutSecrets(t *testing.T) {
	c, err := NewNodeCatalogue()
	if err != nil {
		t.Fatal(err)
	}
	unsupported := &proxyconfig.ProxyConfig{
		Protocol: proxyconfig.ProtocolShadowsocksR,
		Name:     "legacy-ssr", Address: "legacy.example", Port: 443,
		Password: "secret-password", Method: "aes-256-cfb", Protocol_: "auth_sha1_v4", Obfs: "tls1.2_ticket_auth",
	}
	if err := c.Replace("p-runtime", []*proxyconfig.ProxyConfig{unsupported, testSubscriptionNode("modern", "modern.example", "secret-modern")}); err != nil {
		t.Fatal(err)
	}
	views := c.List("p-runtime", true)
	if len(views) != 2 {
		t.Fatalf("views=%d", len(views))
	}
	var legacy, modern MaterializedNodeView
	for _, view := range views {
		if view.Protocol == proxyconfig.ProtocolShadowsocksR {
			legacy = view
		} else if view.Protocol == proxyconfig.ProtocolVLESS {
			modern = view
		}
	}
	if legacy.RuntimeActivatable || len(legacy.RuntimeCores) != 0 || legacy.RuntimeReason == "" {
		t.Fatalf("legacy SSR runtime truth mismatch: %+v", legacy)
	}
	if !modern.RuntimeActivatable || len(modern.RuntimeCores) != 2 || modern.RuntimeReason != "" {
		t.Fatalf("modern VLESS runtime truth mismatch: %+v", modern)
	}
	encoded, _ := json.Marshal(views)
	text := string(encoded)
	for _, secret := range []string{"secret-password", "secret-modern"} {
		if strings.Contains(text, secret) {
			t.Fatalf("runtime compatibility view leaked %q: %s", secret, text)
		}
	}
}
