package provision

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerateVLESSDevcontainerUsesXHTTPAndPinnedVersion(t *testing.T) {
	bundle, err := GenerateVLESSDevcontainer(VLESSDevcontainerSpec{
		UUID:        "123e4567-e89b-42d3-a456-426614174000",
		XrayVersion: "26.3.27",
		Port:        8443,
		Path:        "/edge",
		Mode:        "stream-up",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Files) != 3 {
		t.Fatalf("files=%d", len(bundle.Files))
	}
	var config string
	for _, f := range bundle.Files {
		if f.Path == ".devcontainer/xray-config.json" {
			config = f.Content
		}
		if f.Path == ".devcontainer/devcontainer.json" && !strings.Contains(f.Content, "v26.3.27") {
			t.Fatalf("version pin missing from devcontainer: %s", f.Content)
		}
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(config), &decoded); err != nil {
		t.Fatal(err)
	}
	inbounds := decoded["inbounds"].([]any)
	stream := inbounds[0].(map[string]any)["streamSettings"].(map[string]any)
	if stream["method"] != "xhttp" {
		t.Fatalf("method=%v", stream["method"])
	}
	xhttp := stream["xhttpSettings"].(map[string]any)
	if xhttp["path"] != "/edge" || xhttp["mode"] != "stream-up" {
		t.Fatalf("xhttp=%v", xhttp)
	}
}

func TestGenerateVLESSDevcontainerRejectsInvalidInputs(t *testing.T) {
	base := VLESSDevcontainerSpec{UUID: "123e4567-e89b-42d3-a456-426614174000", XrayVersion: "v26.3.27"}
	bad := base
	bad.UUID = "nope"
	if _, err := GenerateVLESSDevcontainer(bad); err == nil {
		t.Fatal("invalid UUID accepted")
	}
	bad = base
	bad.Mode = "mystery"
	if _, err := GenerateVLESSDevcontainer(bad); err == nil {
		t.Fatal("invalid xhttp mode accepted")
	}
	bad = base
	bad.Path = "relative"
	if _, err := GenerateVLESSDevcontainer(bad); err == nil {
		t.Fatal("relative path accepted")
	}
}
