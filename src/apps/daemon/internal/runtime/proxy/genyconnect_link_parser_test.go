package proxy

import (
	"encoding/base64"
	"testing"
)

func TestGenyLinkParser_ParseVmess(t *testing.T) {
	lp := NewGenyLinkParser()

	// VMess JSON encoded base64 link
	vmessJSON := `{
		"v": "2",
		"ps": "Vmess Test Server",
		"add": "vmess.example.com",
		"port": 443,
		"id": "uuid-here-1234",
		"aid": 0,
		"scy": "auto",
		"net": "ws",
		"type": "none",
		"host": "host.example.com",
		"path": "/ws",
		"tls": "tls",
		"sni": "sni.example.com"
	}`
	encoded := decodeFlexibleBase64Encode(vmessJSON)
	rawLink := "vmess://" + encoded

	profile, err := lp.Parse(rawLink)
	if err != nil {
		t.Fatalf("Failed to parse VMess link: %v", err)
	}

	if profile.Protocol != "vmess" {
		t.Errorf("Expected protocol 'vmess', got '%s'", profile.Protocol)
	}
	if profile.Address != "vmess.example.com" {
		t.Errorf("Expected address 'vmess.example.com', got '%s'", profile.Address)
	}
	if profile.Port != 443 {
		t.Errorf("Expected port 443, got %d", profile.Port)
	}
	if profile.UserID != "uuid-here-1234" {
		t.Errorf("Expected id 'uuid-here-1234', got '%s'", profile.UserID)
	}
	if profile.Network != "ws" {
		t.Errorf("Expected network 'ws', got '%s'", profile.Network)
	}
	if profile.Path != "/ws" {
		t.Errorf("Expected path '/ws', got '%s'", profile.Path)
	}
	if profile.SNI != "sni.example.com" {
		t.Errorf("Expected SNI 'sni.example.com', got '%s'", profile.SNI)
	}
}

func TestGenyLinkParser_ParseVless(t *testing.T) {
	lp := NewGenyLinkParser()

	rawLink := "vless://uuid-here-5678@vless.example.com:443?encryption=none&security=reality&sni=sni.vless.com&fp=chrome&pbk=publickeyhere&sid=shortid#Vless+Reality+Test"
	profile, err := lp.Parse(rawLink)
	if err != nil {
		t.Fatalf("Failed to parse VLESS link: %v", err)
	}

	if profile.Protocol != "vless" {
		t.Errorf("Expected protocol 'vless', got '%s'", profile.Protocol)
	}
	if profile.UserID != "uuid-here-5678" {
		t.Errorf("Expected userid 'uuid-here-5678', got '%s'", profile.UserID)
	}
	if profile.Address != "vless.example.com" {
		t.Errorf("Expected address 'vless.example.com', got '%s'", profile.Address)
	}
	if profile.Port != 443 {
		t.Errorf("Expected port 443, got %d", profile.Port)
	}
	if profile.Security != "reality" {
		t.Errorf("Expected security 'reality', got '%s'", profile.Security)
	}
	if profile.PublicKey != "publickeyhere" {
		t.Errorf("Expected pbk 'publickeyhere', got '%s'", profile.PublicKey)
	}
	if profile.ShortID != "shortid" {
		t.Errorf("Expected sid 'shortid', got '%s'", profile.ShortID)
	}
	if profile.Name != "Vless+Reality+Test" && profile.Name != "Vless Reality Test" {
		t.Errorf("Expected name 'Vless+Reality+Test' or 'Vless Reality Test', got '%s'", profile.Name)
	}
}

func TestGenyLinkParser_ParseTrojan(t *testing.T) {
	lp := NewGenyLinkParser()

	rawLink := "trojan://password123@trojan.example.com:443?security=tls&sni=sni.trojan.com#Trojan+Test"
	profile, err := lp.Parse(rawLink)
	if err != nil {
		t.Fatalf("Failed to parse Trojan link: %v", err)
	}

	if profile.Protocol != "trojan" {
		t.Errorf("Expected protocol 'trojan', got '%s'", profile.Protocol)
	}
	if profile.UserID != "password123" {
		t.Errorf("Expected password 'password123', got '%s'", profile.UserID)
	}
	if profile.Address != "trojan.example.com" {
		t.Errorf("Expected address 'trojan.example.com', got '%s'", profile.Address)
	}
	if profile.Port != 443 {
		t.Errorf("Expected port 443, got %d", profile.Port)
	}
	if profile.SNI != "sni.trojan.com" {
		t.Errorf("Expected SNI 'sni.trojan.com', got '%s'", profile.SNI)
	}
}

func TestGenyLinkParser_ParseShadowsocks(t *testing.T) {
	lp := NewGenyLinkParser()

	// ss://aes-256-gcm:pass123@ss.example.com:8388#SS+Test
	userInfo := decodeFlexibleBase64Encode("aes-256-gcm:pass123")
	rawLink := "ss://" + userInfo + "@ss.example.com:8388#SS+Test"

	profile, err := lp.Parse(rawLink)
	if err != nil {
		t.Fatalf("Failed to parse Shadowsocks link: %v", err)
	}

	if profile.Protocol != "shadowsocks" {
		t.Errorf("Expected protocol 'shadowsocks', got '%s'", profile.Protocol)
	}
	if profile.Encryption != "aes-256-gcm" {
		t.Errorf("Expected encryption 'aes-256-gcm', got '%s'", profile.Encryption)
	}
	if profile.Password != "pass123" {
		t.Errorf("Expected password 'pass123', got '%s'", profile.Password)
	}
	if profile.Address != "ss.example.com" {
		t.Errorf("Expected address 'ss.example.com', got '%s'", profile.Address)
	}
	if profile.Port != 8388 {
		t.Errorf("Expected port 8388, got %d", profile.Port)
	}
}

func decodeFlexibleBase64Encode(s string) string {
	importBase64 := func(data []byte) string {
		encoded := base64.StdEncoding.EncodeToString(data)
		return encoded
	}
	return importBase64([]byte(s))
}
