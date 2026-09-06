package proxyconfig

import (
	"fmt"
	"strings"
)

// BuildXrayTLSSettings translates canonical TLS intent into current Xray TLS
// fields. It intentionally never emits the removed allowInsecure option.
func BuildXrayTLSSettings(p *ProxyConfig) (map[string]interface{}, error) {
	if !p.TLS || strings.EqualFold(p.Security, "reality") {
		return nil, nil
	}
	if p.SkipCertVerify && p.PinnedPeerCertSHA256 == "" {
		return nil, fmt.Errorf("legacy insecure TLS requires an explicit peer certificate pin")
	}
	out := map[string]interface{}{}
	if p.SNI != "" {
		out["serverName"] = p.SNI
	} else if p.Address != "" {
		out["serverName"] = p.Address
	}
	if p.Fingerprint != "" {
		out["fingerprint"] = p.Fingerprint
	}
	if len(p.ALPN) > 0 {
		out["alpn"] = append([]string(nil), p.ALPN...)
	}
	if p.CipherSuites != "" {
		out["cipherSuites"] = p.CipherSuites
	}
	if p.ECHConfigList != "" {
		out["echConfigList"] = p.ECHConfigList
	}
	if p.VerifyPeerCertByName != "" {
		out["verifyPeerCertByName"] = p.VerifyPeerCertByName
	}
	if p.PinnedPeerCertSHA256 != "" {
		out["pinnedPeerCertSha256"] = p.PinnedPeerCertSHA256
	}
	return out, nil
}
