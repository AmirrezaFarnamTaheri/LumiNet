package proxyconfig

import (
	"fmt"
	"strconv"
	"strings"
)

const maxHysteria2PortHoppingEntries = 32

// ParseHysteria2PortHopping validates a comma-separated Hysteria2 mport list.
// A-B ranges are preserved for Xray-side validation; sing-box uses A:B.
func ParseHysteria2PortHopping(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > maxHysteria2PortHoppingEntries {
		return nil, fmt.Errorf("hysteria2 mport exceeds %d entries", maxHysteria2PortHoppingEntries)
	}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty hysteria2 mport entry")
		}
		sep := ""
		if strings.Contains(part, "-") {
			sep = "-"
		} else if strings.Contains(part, ":") {
			sep = ":"
		}
		if sep == "" {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid hysteria2 port %q", part)
			}
			out = append(out, strconv.Itoa(p))
			continue
		}
		bounds := strings.Split(part, sep)
		if len(bounds) != 2 {
			return nil, fmt.Errorf("invalid hysteria2 port range %q", part)
		}
		lo, e1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
		hi, e2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
		if e1 != nil || e2 != nil || lo < 1 || hi > 65535 || lo > hi {
			return nil, fmt.Errorf("invalid hysteria2 port range %q", part)
		}
		out = append(out, fmt.Sprintf("%d:%d", lo, hi))
	}
	return out, nil
}

// BuildXrayHysteria2Settings emits the Hysteria transport contract used by
// Xray. Port hopping remains deliberately un-emitted because a share-link mport
// expression is not automatically equivalent to Xray FinalMask udpHop policy.
func BuildXrayHysteria2Settings(p *ProxyConfig) (map[string]interface{}, error) {
	if p.Protocol != ProtocolHysteria2 {
		return nil, nil
	}
	if strings.TrimSpace(p.Hysteria2PortHopping) != "" {
		return nil, fmt.Errorf("hysteria2 port hopping requires an explicit Xray FinalMask udpHop policy")
	}
	if p.Obfuscation != "" && p.FinalMask == "" {
		return nil, fmt.Errorf("native Hysteria2 obfuscation requires an explicit Xray finalmask mapping")
	}
	return map[string]interface{}{"version": 2, "auth": p.Password}, nil
}
