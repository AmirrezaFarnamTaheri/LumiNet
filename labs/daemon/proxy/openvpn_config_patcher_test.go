package proxy

import (
	"strings"
	"testing"
)

func TestPatchOpenVPNConfig(t *testing.T) {
	inputConfig := `
client
dev tun
proto udp
remote vpn.example.com 1194
cipher AES-128-CBC
comp-lzo
ncp-disable
verb 3
`

	patched := PatchOpenVPNConfig(inputConfig)

	// Verify legacy deprecated options are scrubbed
	if !strings.Contains(patched, "# LUMINET COMPAT: scrubbed legacy directive: comp-lzo") {
		t.Errorf("expected comp-lzo to be scrubbed; got:\n%s", patched)
	}
	if !strings.Contains(patched, "# LUMINET COMPAT: scrubbed legacy directive: ncp-disable") {
		t.Errorf("expected ncp-disable to be scrubbed; got:\n%s", patched)
	}

	// Verify cipher → data-ciphers OmidVPN rewrite happened
	if strings.Contains(patched, "cipher AES-128-CBC\n") {
		t.Errorf("expected legacy cipher AES-128-CBC to be rewritten, but it was preserved")
	}
	if !strings.Contains(patched, "# LUMINET CIPHER PATCH") {
		t.Errorf("expected LUMINET CIPHER PATCH comment; got:\n%s", patched)
	}
	if !strings.Contains(patched, "data-ciphers AES-128-CBC:AES-256-GCM:AES-128-GCM") {
		t.Errorf("expected data-ciphers preference list; got:\n%s", patched)
	}

	// Verify modern defaults are injected
	if !strings.Contains(patched, "tls-version-min 1.2") {
		t.Errorf("expected minimum TLS version to be set; got:\n%s", patched)
	}
	if !strings.Contains(patched, "persist-key") {
		t.Errorf("expected persist-key to be injected; got:\n%s", patched)
	}
	if !strings.Contains(patched, "persist-tun") {
		t.Errorf("expected persist-tun to be injected; got:\n%s", patched)
	}
	if !strings.Contains(patched, "keepalive 10 120") {
		t.Errorf("expected keepalive to be injected; got:\n%s", patched)
	}

	// Verify kept options are preserved
	if !strings.Contains(patched, "dev tun") {
		t.Errorf("expected dev tun to be preserved")
	}
	if !strings.Contains(patched, "proto udp") {
		t.Errorf("expected proto udp to be preserved")
	}
}

func TestApplyInlineCipherFix(t *testing.T) {
	// OmidVPN-style: exact regex replacement `cipher ` → `data-ciphers `
	input := "cipher AES-256-GCM\ncipher AES-128-CBC\nproto udp\n"
	patched := ApplyInlineCipherFix(input)

	if strings.Contains(patched, "cipher AES") {
		t.Errorf("expected all 'cipher AES' to be replaced; got:\n%s", patched)
	}
	if !strings.Contains(patched, "data-ciphers AES-256-GCM") {
		t.Errorf("expected data-ciphers AES-256-GCM; got:\n%s", patched)
	}
	if !strings.Contains(patched, "data-ciphers AES-128-CBC") {
		t.Errorf("expected data-ciphers AES-128-CBC; got:\n%s", patched)
	}
	if !strings.Contains(patched, "proto udp") {
		t.Errorf("expected proto udp to be preserved; got:\n%s", patched)
	}
}

func TestPatchOpenVPNConfigPreservesModernDirectives(t *testing.T) {
	// A config that already has data-ciphers should not get duplicated
	input := `client
dev tun
proto tcp
remote 10.0.0.1 443
data-ciphers AES-256-GCM:CHACHA20-POLY1305
tls-version-min 1.3
persist-key
persist-tun
keepalive 10 60
`
	patched := PatchOpenVPNConfig(input)

	// Count occurrences — should not be duplicated
	count := strings.Count(patched, "data-ciphers")
	if count > 1 {
		t.Errorf("expected exactly 1 data-ciphers line, got %d; patched:\n%s", count, patched)
	}
	count = strings.Count(patched, "tls-version-min")
	if count > 1 {
		t.Errorf("expected exactly 1 tls-version-min line, got %d", count)
	}
}

func TestPatchOpenVPNConfigVerbClamped(t *testing.T) {
	input := "verb 9\n"
	patched := PatchOpenVPNConfig(input)
	if strings.Contains(patched, "verb 9") {
		t.Errorf("expected verb 9 to be clamped; got:\n%s", patched)
	}
	if !strings.Contains(patched, "verb 3") {
		t.Errorf("expected verb 3 after clamping; got:\n%s", patched)
	}
}

func TestDefaultPatchOptions(t *testing.T) {
	opts := DefaultPatchOptions()
	if !opts.InlineCipherFix {
		t.Error("expected InlineCipherFix to be true by default")
	}
	if !opts.EnforceTLS12 {
		t.Error("expected EnforceTLS12 to be true by default")
	}
	if opts.MaxVerb != 3 {
		t.Errorf("expected MaxVerb=3, got %d", opts.MaxVerb)
	}
}

func TestPatchOpenVPNConfigWith_InlineFix(t *testing.T) {
	input := "cipher AES-128-CBC\nremote 1.2.3.4 1194\n"
	opts := PatchOpenVPNConfigOptions{InlineCipherFix: true}
	patched := PatchOpenVPNConfigWith(input, opts)
	if !strings.Contains(patched, "data-ciphers AES-128-CBC") {
		t.Errorf("expected inline cipher fix; got:\n%s", patched)
	}
}
