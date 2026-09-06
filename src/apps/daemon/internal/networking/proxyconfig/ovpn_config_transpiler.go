package proxyconfig

import (
	"errors"
	"strconv"
	"strings"
)

// TranspiledOvpnProfile represents parsed and structured OpenVPN settings
type TranspiledOvpnProfile struct {
	RemoteHost string
	RemotePort uint16
	Proto      string // "udp" or "tcp"
	DevType    string // "tun" or "tap"
	Cipher     string
	AuthDigest string
	CACert     string
	ClientCert string
	ClientKey  string
	Routes     []string
}

// OvpnConfigTranspiler converts raw .ovpn configuration text into structured LumiNet proxy configs
type OvpnConfigTranspiler struct{}

// NewOvpnConfigTranspiler creates an instance of the transpiler
func NewOvpnConfigTranspiler() *OvpnConfigTranspiler {
	return &OvpnConfigTranspiler{}
}

// Transpile converts an .ovpn config string into TranspiledOvpnProfile
func (t *OvpnConfigTranspiler) Transpile(rawConfig string) (*TranspiledOvpnProfile, error) {
	lines := strings.Split(rawConfig, "\n")
	profile := &TranspiledOvpnProfile{
		RemotePort: 1194,
		Proto:      "udp",
		DevType:    "tun",
		Cipher:     "AES-256-GCM",
		AuthDigest: "SHA256",
	}

	inTag := ""
	var tagContent strings.Builder

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}

		// Handle embedded XML-like cert tags <ca>, </ca>, etc.
		if strings.HasPrefix(trimmed, "<") && strings.HasSuffix(trimmed, ">") && !strings.HasPrefix(trimmed, "</") {
			inTag = strings.Trim(trimmed, "<>")
			tagContent.Reset()
			continue
		}
		if inTag != "" && trimmed == "</"+inTag+">" {
			switch inTag {
			case "ca":
				profile.CACert = strings.TrimSpace(tagContent.String())
			case "cert":
				profile.ClientCert = strings.TrimSpace(tagContent.String())
			case "key":
				profile.ClientKey = strings.TrimSpace(tagContent.String())
			}
			inTag = ""
			continue
		}

		if inTag != "" {
			tagContent.WriteString(trimmed)
			tagContent.WriteString("\n")
			continue
		}

		parts := strings.Fields(trimmed)
		if len(parts) == 0 {
			continue
		}

		switch parts[0] {
		case "remote":
			if len(parts) >= 2 {
				profile.RemoteHost = parts[1]
			}
			if len(parts) >= 3 {
				if p, err := strconv.ParseUint(parts[2], 10, 16); err == nil {
					profile.RemotePort = uint16(p)
				}
			}
			if len(parts) >= 4 {
				profile.Proto = strings.ToLower(parts[3])
			}
		case "proto":
			if len(parts) >= 2 {
				profile.Proto = strings.ToLower(parts[1])
			}
		case "dev":
			if len(parts) >= 2 {
				profile.DevType = parts[1]
			}
		case "cipher":
			if len(parts) >= 2 {
				profile.Cipher = parts[1]
			}
		case "auth":
			if len(parts) >= 2 {
				profile.AuthDigest = parts[1]
			}
		case "route":
			if len(parts) >= 2 {
				profile.Routes = append(profile.Routes, strings.Join(parts[1:], " "))
			}
		}
	}

	if profile.RemoteHost == "" {
		return nil, errors.New("remote directive missing from configuration")
	}

	return profile, nil
}
