package proxyconfig

import (
	"fmt"
	"net/url"
)

// parseAnyTLS parses a anytls:// URI into a ProxyConfig.
// anytls://password@address:port?sni=example.com&allowInsecure=true&minIdleSessions=5#Remark
func parseAnyTLS(uri string) (*ProxyConfig, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	password := parsed.User.Username()
	if password == "" && parsed.User != nil {
		password = parsed.User.String()
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
	if password == "" {
		return nil, fmt.Errorf("missing password")
	}

	minIdleSessions := 0
	for _, key := range []string{"min_idle_session", "min_idle_sessions", "minIdleSession", "minIdleSessions"} {
		if val := q.Get(key); val != "" {
			fmt.Sscanf(val, "%d", &minIdleSessions)
			break
		}
	}
	idleCheck := q.Get("idle_session_check_interval")
	if idleCheck == "" {
		idleCheck = q.Get("idleSessionCheckInterval")
	}
	idleTimeout := q.Get("idle_session_timeout")
	if idleTimeout == "" {
		idleTimeout = q.Get("idleSessionTimeout")
	}

	return &ProxyConfig{
		Protocol:                       ProtocolAnyTLS,
		Name:                           remark,
		Address:                        host,
		Port:                           port,
		Password:                       password,
		TLS:                            true,
		SNI:                            q.Get("sni"),
		SkipCertVerify:                 queryBool(q, "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify", "skip_cert_verify"),
		AnyTLSIdleSessionCheckInterval: idleCheck,
		AnyTLSIdleSessionTimeout:       idleTimeout,
		MinIdleSessions:                minIdleSessions,
	}, nil
}
