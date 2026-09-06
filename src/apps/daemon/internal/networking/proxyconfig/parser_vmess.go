package proxyconfig

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

func vmessTLSValue(value interface{}) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "tls", "true", "1", "yes", "on":
			return true
		}
	case float64:
		return typed != 0
	}
	return false
}

// parseVMess parses a vmess:// URI into a ProxyConfig.
func parseVMess(uri string) (*ProxyConfig, error) {
	b64 := uri[8:]
	b64 = strings.TrimSpace(b64)
	var remark string
	if idx := strings.Index(b64, "#"); idx != -1 {
		remark = b64[idx+1:]
		b64 = b64[:idx]
	}

	padLen := (4 - (len(b64) % 4)) % 4
	padded := b64 + strings.Repeat("=", padLen)

	var decoded []byte
	var err error

	decoded, err = base64.StdEncoding.DecodeString(padded)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(padded)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(b64)
			if err != nil {
				decoded, err = base64.RawURLEncoding.DecodeString(b64)
				if err != nil {
					return nil, fmt.Errorf("failed to decode base64 VMess: %w", err)
				}
			}
		}
	}

	var vmess struct {
		V               interface{} `json:"v"`
		Ps              string      `json:"ps"`
		Add             string      `json:"add"`
		Port            interface{} `json:"port"`
		Id              string      `json:"id"`
		Aid             interface{} `json:"aid"`
		Scy             string      `json:"scy"`
		Net             string      `json:"net"`
		Type            string      `json:"type"`
		Host            string      `json:"host"`
		Path            string      `json:"path"`
		Tls             interface{} `json:"tls"`
		Sni             string      `json:"sni"`
		Alpn            string      `json:"alpn"`
		Fp              string      `json:"fp"`
		Cs              string      `json:"cs"`
		Ech             string      `json:"ech"`
		Vcn             string      `json:"vcn"`
		Pcs             string      `json:"pcs"`
		FinalMask       string      `json:"fm"`
		Mode            string      `json:"mode"`
		Extra           string      `json:"extra"`
		Spx             string      `json:"spx"`
		AllowInsecure   interface{} `json:"allowInsecure"`
		AllowInsecure2  interface{} `json:"allow_insecure"`
		Insecure        interface{} `json:"insecure"`
		SkipCertVerify  interface{} `json:"skip-cert-verify"`
		SkipCertVerify2 interface{} `json:"skip_cert_verify"`
	}

	if err := json.Unmarshal(decoded, &vmess); err != nil {
		return nil, fmt.Errorf("failed to parse VMess JSON: %w", err)
	}

	port := 443
	switch p := vmess.Port.(type) {
	case float64:
		port = int(p)
	case string:
		fmt.Sscanf(p, "%d", &port)
	}

	alterID := 0
	switch a := vmess.Aid.(type) {
	case float64:
		alterID = int(a)
	case string:
		fmt.Sscanf(a, "%d", &alterID)
	}

	if vmess.Add == "" {
		return nil, fmt.Errorf("missing server address")
	}
	if vmess.Id == "" {
		return nil, fmt.Errorf("missing user ID (uuid)")
	}

	name := vmess.Ps
	if name == "" {
		name = remark
	}

	var alpn []string
	if vmess.Alpn != "" {
		for _, item := range strings.Split(vmess.Alpn, ",") {
			if item = strings.TrimSpace(item); item != "" {
				alpn = append(alpn, item)
			}
		}
	}

	return &ProxyConfig{
		Protocol:             ProtocolVMess,
		Name:                 name,
		Address:              vmess.Add,
		Port:                 port,
		UUID:                 vmess.Id,
		AlterID:              alterID,
		Security:             vmess.Scy,
		Transport:            CanonicalXHTTPTransport(vmess.Net),
		Host:                 vmess.Host,
		Path:                 vmess.Path,
		TLS:                  vmessTLSValue(vmess.Tls),
		SNI:                  vmess.Sni,
		ALPN:                 alpn,
		Fingerprint:          vmess.Fp,
		CipherSuites:         vmess.Cs,
		ECHConfigList:        vmess.Ech,
		VerifyPeerCertByName: vmess.Vcn,
		PinnedPeerCertSHA256: vmess.Pcs,
		FinalMask:            vmess.FinalMask,
		XHTTPMode:            vmess.Mode,
		XHTTPExtra:           vmess.Extra,
		SpiderX:              vmess.Spx,
		SkipCertVerify:       looseBoolValue(vmess.AllowInsecure, vmess.AllowInsecure2, vmess.Insecure, vmess.SkipCertVerify, vmess.SkipCertVerify2),
	}, nil
}
