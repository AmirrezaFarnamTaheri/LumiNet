package proxyconfig

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// parseShadowsocks parses an ss:// URI into a ProxyConfig.
func parseShadowsocks(uri string) (*ProxyConfig, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	remark, _ := url.PathUnescape(parsed.Fragment)
	var method, password, host string
	port := 8388

	// Check if SIP002 (method:password base64-encoded in user part) or Legacy (whole block base64-encoded)
	if parsed.User != nil {
		// SIP002 permits either plaintext method:password userinfo or a
		// base64-encoded method:password token. Prefer the explicit password
		// form first so SS2022 key material containing additional ':' bytes is
		// preserved instead of being mistaken for base64.
		if pass, ok := parsed.User.Password(); ok && parsed.User.Username() != "" && pass != "" {
			method = parsed.User.Username()
			password = pass
		} else {
			userinfo := parsed.User.Username()
			decoded, decodeErr := decodeShadowsocksBase64(userinfo)
			if decodeErr == nil {
				parts := strings.SplitN(string(decoded), ":", 2)
				if len(parts) == 2 {
					method = parts[0]
					password = parts[1]
				}
			}
		}
		host = parsed.Hostname()
		if parsed.Port() != "" {
			fmt.Sscanf(parsed.Port(), "%d", &port)
		}
	} else {
		// Legacy format or standard base64 url block
		opaque := parsed.Opaque
		if opaque == "" {
			opaque = parsed.Host
		}
		// Clean fragment
		if idx := strings.Index(opaque, "#"); idx != -1 {
			opaque = opaque[:idx]
		}

		decoded, decodeErr := decodeShadowsocksBase64(opaque)
		if decodeErr != nil {
			return nil, fmt.Errorf("failed to decode base64 Shadowsocks URI: %w", decodeErr)
		}
		// Legacy payload is method:password@host:port. Passwords seen in real
		// feeds may themselves contain '@', so the endpoint separator is the
		// final at-sign rather than the first.
		decodedText := string(decoded)
		at := strings.LastIndex(decodedText, "@")
		if at > 0 && at < len(decodedText)-1 {
			userparts := strings.SplitN(decodedText[:at], ":", 2)
			if len(userparts) == 2 {
				method = userparts[0]
				password = userparts[1]
			}
			endpoint := decodedText[at+1:]
			if h, p, splitErr := net.SplitHostPort(endpoint); splitErr == nil {
				host = h
				fmt.Sscanf(p, "%d", &port)
			}
		}
	}

	q := parsed.Query()
	plugin := q.Get("plugin")
	pluginOpts := q.Get("plugin-opts")
	prefix := q.Get("prefix")

	if host == "" {
		return nil, fmt.Errorf("missing server address")
	}
	if method == "" || password == "" {
		return nil, fmt.Errorf("missing Shadowsocks method or password")
	}

	return &ProxyConfig{
		Protocol:   ProtocolShadowsocks,
		Name:       remark,
		Address:    host,
		Port:       port,
		Method:     method,
		Password:   password,
		Plugin:     plugin,
		PluginOpts: pluginOpts,
		Prefix:     prefix,
	}, nil
}

func decodeShadowsocksBase64(value string) ([]byte, error) {
	padded := value + strings.Repeat("=", (4-len(value)%4)%4)
	encodings := []*base64.Encoding{base64.URLEncoding, base64.StdEncoding, base64.RawURLEncoding, base64.RawStdEncoding}
	var lastErr error
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(padded)
		if err == nil {
			return decoded, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func validateShadowsocks2022Key(method, password string) error {
	method = strings.ToLower(strings.TrimSpace(method))
	want := 0
	switch method {
	case "2022-blake3-aes-128-gcm":
		want = 16
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		want = 32
	default:
		if strings.HasPrefix(method, "2022-blake3-") {
			return fmt.Errorf("unsupported Shadowsocks 2022 method %q", method)
		}
		return nil
	}

	parts := strings.Split(password, ":")
	if len(parts) == 0 {
		return fmt.Errorf("missing Shadowsocks 2022 key material")
	}
	for i, part := range parts {
		if strings.TrimSpace(part) == "" {
			return fmt.Errorf("empty Shadowsocks 2022 key component %d", i+1)
		}
		decoded, err := decodeShadowsocksBase64(part)
		if err != nil {
			return fmt.Errorf("invalid Shadowsocks 2022 key component %d: %w", i+1, err)
		}
		if len(decoded) != want {
			return fmt.Errorf("invalid Shadowsocks 2022 key component %d length: got %d bytes, want %d", i+1, len(decoded), want)
		}
	}
	return nil
}

// parseShadowsocksR parses an ssr:// URI into a ProxyConfig.
// Format: ssr://<base64(host:port:protocol:method:obfs:base64pass/?params)>
func parseShadowsocksR(uri string) (*ProxyConfig, error) {
	b64 := uri[6:]
	b64 = strings.TrimSpace(b64)
	if idx := strings.Index(b64, "#"); idx != -1 {
		b64 = b64[:idx]
	}

	padLen := (4 - (len(b64) % 4)) % 4
	padded := b64 + strings.Repeat("=", padLen)

	decoded, err := base64.URLEncoding.DecodeString(padded)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(padded)
		if err != nil {
			return nil, fmt.Errorf("failed to decode ShadowsocksR base64: %w", err)
		}
	}

	// Decoded is server:port:protocol:method:obfs:base64pass/?obfsparam=...&protoparam=...
	parts := strings.SplitN(string(decoded), "/?", 2)
	main := strings.Split(parts[0], ":")
	if len(main) < 6 {
		return nil, fmt.Errorf("invalid ShadowsocksR main payload parts")
	}

	server := main[0]
	port := 8388
	fmt.Sscanf(main[1], "%d", &port)
	protocol := main[2]
	method := main[3]
	obfs := main[4]

	passB64 := main[5]
	passPad := (4 - (len(passB64) % 4)) % 4
	passDec, _ := base64.URLEncoding.DecodeString(passB64 + strings.Repeat("=", passPad))
	if len(passDec) == 0 {
		passDec, _ = base64.StdEncoding.DecodeString(passB64 + strings.Repeat("=", passPad))
	}

	var obfsParam, protoParam, remark string
	if len(parts) > 1 {
		q, _ := url.ParseQuery(parts[1])
		if op := q.Get("obfsparam"); op != "" {
			opPad := (4 - (len(op) % 4)) % 4
			opDec, _ := base64.URLEncoding.DecodeString(op + strings.Repeat("=", opPad))
			obfsParam = string(opDec)
		}
		if pp := q.Get("protoparam"); pp != "" {
			ppPad := (4 - (len(pp) % 4)) % 4
			ppDec, _ := base64.URLEncoding.DecodeString(pp + strings.Repeat("=", ppPad))
			protoParam = string(ppDec)
		}
		if rem := q.Get("remarks"); rem != "" {
			remPad := (4 - (len(rem) % 4)) % 4
			remDec, _ := base64.URLEncoding.DecodeString(rem + strings.Repeat("=", remPad))
			remark = string(remDec)
		}
	}

	if server == "" {
		return nil, fmt.Errorf("missing server address")
	}
	if method == "" || len(passDec) == 0 {
		return nil, fmt.Errorf("missing ShadowsocksR method or password")
	}

	return &ProxyConfig{
		Protocol:      ProtocolShadowsocksR,
		Name:          remark,
		Address:       server,
		Port:          port,
		Method:        method,
		Password:      string(passDec),
		Protocol_:     protocol,
		Obfs:          obfs,
		ObfsParam:     obfsParam,
		ProtocolParam: protoParam,
	}, nil
}
