package sub

import (
	"strings"
	"testing"

	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

func TestPostRefactor232OutlineInviteUnwrapsLocally(t *testing.T) {
	invite := "https://invite.example/#ss%3A%2F%2FYWVzLTEyOC1nY206cGFzc3dvcmQ%3D%40example.com%3A8388%23SSTest"
	configs, err := ParseContent(invite)
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 1 || configs[0] == nil || configs[0].Protocol != proxyconfig.ProtocolShadowsocks {
		t.Fatalf("unexpected configs: %+v", configs)
	}
	if configs[0].Address != "example.com" || configs[0].Port != 8388 {
		t.Fatalf("unexpected node: %+v", configs[0])
	}
}

func TestPostRefactor232OutlineInviteMalformedStaticFragmentFailsClosed(t *testing.T) {
	_, err := ParseContent("https://invite.example/#ss%3A%2F%2Fnot-valid")
	if err == nil {
		t.Fatal("malformed Outline static invite was accepted")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "outline") {
		t.Fatalf("error does not preserve import boundary: %v", err)
	}
}

func TestPostRefactor232OutlineDynamicURLIsNotFetchedByContentParser(t *testing.T) {
	_, err := ParseContent("ssconf://provider.example/key")
	if err == nil {
		t.Fatal("dynamic ssconf should remain unresolved in local content parsing")
	}
}
