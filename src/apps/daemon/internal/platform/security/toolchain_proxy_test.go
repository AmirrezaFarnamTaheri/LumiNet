package security

import (
	"strings"
	"testing"
)

func TestToolchainProxyWrapper(t *testing.T) {
	wrapper := NewToolchainProxyWrapper("http://127.0.0.1:8080", "socks5://127.0.0.1:1080")

	git := wrapper.GenerateSnippet(ToolchainGit)
	if !strings.Contains(git, "proxy = http://127.0.0.1:8080") {
		t.Fatalf("expected git proxy set, got %s", git)
	}

	gradle := wrapper.GenerateSnippet(ToolchainGradle)
	if !strings.Contains(gradle, "systemProp.http.proxyPort=8080") {
		t.Fatalf("expected gradle port set, got %s", gradle)
	}

	envs := wrapper.GenerateEnvVars()
	if envs["ALL_PROXY"] != "socks5://127.0.0.1:1080" {
		t.Fatalf("expected ALL_PROXY set, got %s", envs["ALL_PROXY"])
	}
}
