package proxyconfig

import (
	"encoding/json"
	"fmt"
	"strings"
)

// MaxXHTTPExtraBytes bounds share-controlled XHTTP extra JSON.
const MaxXHTTPExtraBytes = 16 * 1024

func CanonicalXHTTPTransport(transport string) string {
	switch strings.ToLower(strings.TrimSpace(transport)) {
	case "xhttp", "splithttp":
		return "xhttp"
	default:
		return strings.ToLower(strings.TrimSpace(transport))
	}
}

func validateXHTTPMode(mode string) error {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "auto", "packet-up", "stream-up", "stream-one":
		return nil
	default:
		return fmt.Errorf("unsupported xhttp mode %q", mode)
	}
}

func decodeXHTTPExtra(raw string) (map[string]interface{}, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if len(raw) > MaxXHTTPExtraBytes {
		return nil, fmt.Errorf("xhttp extra exceeds %d bytes", MaxXHTTPExtraBytes)
	}
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("invalid xhttp extra JSON: %w", err)
	}
	if out == nil {
		return nil, fmt.Errorf("xhttp extra must be a JSON object")
	}
	return out, nil
}

// BuildXrayXHTTPSettings constructs the target-owned subset of Xray XHTTP
// settings. Share metadata outside this contract is rejected rather than
// silently guessed.
func BuildXrayXHTTPSettings(p *ProxyConfig) (map[string]interface{}, error) {
	if CanonicalXHTTPTransport(p.Transport) != "xhttp" {
		return nil, nil
	}
	if err := validateXHTTPMode(p.XHTTPMode); err != nil {
		return nil, err
	}
	out := map[string]interface{}{}
	if p.Host != "" {
		out["host"] = p.Host
	}
	if p.Path != "" {
		out["path"] = p.Path
	}
	if mode := strings.ToLower(strings.TrimSpace(p.XHTTPMode)); mode != "" {
		out["mode"] = mode
	}
	extra, err := decodeXHTTPExtra(p.XHTTPExtra)
	if err != nil {
		return nil, err
	}
	if extra != nil {
		out["extra"] = extra
	}
	return out, nil
}
