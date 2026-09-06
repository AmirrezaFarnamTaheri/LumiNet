package backhaul

import (
	"strings"
	"testing"
)

func TestServerConfigTOML(t *testing.T) {
	cfg := NewDefaultServerConfig(8080, "secret-token")
	cfg.Transport = "wssmux"
	cfg.TLSCert = "/etc/cert.crt"
	cfg.TLSKey = "/etc/cert.key"
	cfg.Ports = []string{"80:8080", "443:8443"}

	tomlStr := cfg.GenerateTOML()

	if !strings.Contains(tomlStr, `bind_addr = "0.0.0.0:8080"`) {
		t.Errorf("expected bind_addr to be 0.0.0.0:8080, got %s", tomlStr)
	}
	if !strings.Contains(tomlStr, `transport = "wssmux"`) {
		t.Errorf("expected transport to be wssmux, got %s", tomlStr)
	}
	if !strings.Contains(tomlStr, `token = "secret-token"`) {
		t.Errorf("expected token, got %s", tomlStr)
	}
	if !strings.Contains(tomlStr, `tls_cert = "/etc/cert.crt"`) {
		t.Errorf("expected tls_cert, got %s", tomlStr)
	}
	if !strings.Contains(tomlStr, `"80:8080"`) {
		t.Errorf("expected port mapping, got %s", tomlStr)
	}
}

func TestClientConfigTOML(t *testing.T) {
	cfg := NewDefaultClientConfig("1.2.3.4:8080", "secret-token")
	cfg.Transport = "wsmux"
	cfg.EdgeIP = "104.16.0.1"

	tomlStr := cfg.GenerateTOML()

	if !strings.Contains(tomlStr, `remote_addr = "1.2.3.4:8080"`) {
		t.Errorf("expected remote_addr, got %s", tomlStr)
	}
	if !strings.Contains(tomlStr, `edge_ip = "104.16.0.1"`) {
		t.Errorf("expected edge_ip, got %s", tomlStr)
	}
	if !strings.Contains(tomlStr, `transport = "wsmux"`) {
		t.Errorf("expected transport wsmux, got %s", tomlStr)
	}
}

func TestParseServerConfig(t *testing.T) {
	tomlInput := `
[server]
bind_addr = "0.0.0.0:9000"
transport = "tcpmux"
token = "tok123"
ports = [
  "80:8080",
  "443:8443"
]
`
	cfg, err := ParseServerConfig(tomlInput)
	if err != nil {
		t.Fatalf("ParseServerConfig failed: %v", err)
	}

	if cfg.BindAddr != "0.0.0.0:9000" {
		t.Errorf("expected bind_addr 0.0.0.0:9000, got %s", cfg.BindAddr)
	}
	if cfg.Transport != "tcpmux" {
		t.Errorf("expected transport tcpmux, got %s", cfg.Transport)
	}
	if cfg.Token != "tok123" {
		t.Errorf("expected token tok123, got %s", cfg.Token)
	}
	if len(cfg.Ports) != 2 || cfg.Ports[0] != "80:8080" || cfg.Ports[1] != "443:8443" {
		t.Errorf("unexpected ports: %+v", cfg.Ports)
	}
}
