package proxyconfig

import (
	"fmt"
	"net/url"
	"strings"
)

// parseJuicity parses a juicity:// URI into a ProxyConfig.
// juicity://uuid:password@address:port?sni=example.com&allowInsecure=true&congestion=bbr&pinnedCertchain=sha256#Remark
func parseJuicity(uri string) (*ProxyConfig, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	var uuidStr, password string
	if parsed.User != nil {
		uuidStr = parsed.User.Username()
		password, _ = parsed.User.Password()
		if password == "" && strings.Contains(parsed.User.String(), ":") {
			// fallback in case standard parsing missed username:password split due to encoding
			parts := strings.SplitN(parsed.User.String(), ":", 2)
			uuidStr = parts[0]
			password = parts[1]
		} else if uuidStr == "" {
			uuidStr = parsed.User.String()
		}
	}

	port := 443
	if parsed.Port() != "" {
		fmt.Sscanf(parsed.Port(), "%d", &port)
	}

	q := parsed.Query()
	remark, _ := url.PathUnescape(parsed.Fragment)

	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing server address")
	}
	if uuidStr == "" && password == "" {
		return nil, fmt.Errorf("missing UUID or password")
	}

	return &ProxyConfig{
		Protocol:              ProtocolJuicity,
		Name:                  remark,
		Address:               host,
		Port:                  port,
		UUID:                  uuidStr,
		Password:              password,
		TLS:                   true,
		SNI:                   q.Get("sni"),
		SkipCertVerify:        queryBool(q, "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify", "skip_cert_verify"),
		CongestionControl:     q.Get("congestion"),
		PinnedCertChainSHA256: q.Get("pinnedCertchain"),
	}, nil
}
