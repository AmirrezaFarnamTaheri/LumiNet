package proxyconfig

import (
	"fmt"
	"net/url"
	"strings"
)

// parseTrojan parses a trojan:// URI into a ProxyConfig.
// Format: trojan://<password>@<host>:<port>?sni=<sni>&type=<transport>#<name>
func parseTrojan(uri string) (*ProxyConfig, error) {
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
	transport := CanonicalXHTTPTransport(q.Get("type"))
	if transport == "" {
		transport = "tcp"
	}

	remark, _ := url.PathUnescape(parsed.Fragment)

	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing server address")
	}
	if password == "" {
		return nil, fmt.Errorf("missing password")
	}

	alpn := []string{}
	if raw := q.Get("alpn"); raw != "" {
		for _, item := range strings.Split(raw, ",") {
			if item = strings.TrimSpace(item); item != "" {
				alpn = append(alpn, item)
			}
		}
	}
	return &ProxyConfig{
		Protocol:             ProtocolTrojan,
		Name:                 remark,
		Address:              host,
		Port:                 port,
		Password:             password,
		Transport:            transport,
		TLS:                  true,
		SNI:                  q.Get("sni"),
		Path:                 q.Get("path"),
		Host:                 q.Get("host"),
		Fingerprint:          q.Get("fp"),
		CipherSuites:         q.Get("cs"),
		ECHConfigList:        q.Get("ech"),
		VerifyPeerCertByName: q.Get("vcn"),
		PinnedPeerCertSHA256: q.Get("pcs"),
		FinalMask:            q.Get("fm"),
		XHTTPMode:            q.Get("mode"),
		XHTTPExtra:           q.Get("extra"),
		ALPN:                 alpn,
		SkipCertVerify:       queryBool(q, "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify", "skip_cert_verify"),
	}, nil
}
