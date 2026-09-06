package sub

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

const maxOutlineInviteBytes = 8192

// unwrapOutlineStaticInvite extracts a static ss:// key from an HTTP(S) invite
// fragment. It is deliberately local-only: dynamic ssconf:// keys are not
// fetched or resolved here and remain under the guarded subscription egress
// boundary.
func unwrapOutlineStaticInvite(raw string) (string, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxOutlineInviteBytes {
		return raw, false, nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Fragment == "" {
		return raw, false, nil
	}
	fragment := u.Fragment
	if decoded, err := url.PathUnescape(fragment); err == nil {
		fragment = decoded
	}
	idx := strings.Index(strings.ToLower(fragment), "ss://")
	if idx < 0 {
		return raw, false, nil
	}
	candidate := strings.TrimSpace(fragment[idx:])
	cfg, err := proxyconfig.ParseProxyURI(candidate)
	if err != nil || cfg == nil || cfg.Protocol != proxyconfig.ProtocolShadowsocks {
		if err == nil {
			err = fmt.Errorf("fragment is not a Shadowsocks access key")
		}
		return raw, false, fmt.Errorf("invalid Outline invite fragment: %w", err)
	}
	return candidate, true, nil
}
