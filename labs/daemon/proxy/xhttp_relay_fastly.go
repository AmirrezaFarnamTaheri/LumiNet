// Package proxy implements Fastly CDN XHTTP relay config ported from XHTTPRelayFastly-master.
// Source: XHTTPRelayFastly-master/src/index.js
// Target: server/internal/proxy/xhttp_relay_fastly.go

package proxy

import "strings"

// XHTTPRelayFastlyConfig holds Fastly-specific relay configuration.
// Source: XHTTPRelayFastly-master/src/index.js ConfigStore fields and global constants.
type XHTTPRelayFastlyConfig struct {
	TargetBase      string
	TargetHostname  string
	RelayPath       string
	PublicRelayPath string
	ConfigStoreName string
}

// NewXHTTPRelayFastlyConfig returns defaults matching Fastly relay upstream.
func NewXHTTPRelayFastlyConfig() *XHTTPRelayFastlyConfig {
	return &XHTTPRelayFastlyConfig{
		TargetBase:      "https://example.com:443",
		TargetHostname:  "example.com",
		RelayPath:       "/api",
		PublicRelayPath: "/api",
		ConfigStoreName: "relay_config",
	}
}

func (c *XHTTPRelayFastlyConfig) GetTargetBase() string       { return c.TargetBase }
func (c *XHTTPRelayFastlyConfig) SetTargetBase(v string)      { c.TargetBase = v }
func (c *XHTTPRelayFastlyConfig) GetTargetHostname() string   { return c.TargetHostname }
func (c *XHTTPRelayFastlyConfig) SetTargetHostname(v string)  { c.TargetHostname = v }
func (c *XHTTPRelayFastlyConfig) GetRelayPath() string        { return c.RelayPath }
func (c *XHTTPRelayFastlyConfig) SetRelayPath(v string)       { c.RelayPath = v }
func (c *XHTTPRelayFastlyConfig) GetPublicRelayPath() string  { return c.PublicRelayPath }
func (c *XHTTPRelayFastlyConfig) SetPublicRelayPath(v string) { c.PublicRelayPath = v }

// XHTTPRelayAllowedMethods returns the upstream-allowed HTTP methods.
// Source: XHTTPRelayFastly-master/src/index.js ALLOWED_METHODS
var XHTTPRelayAllowedMethods = []string{"GET", "HEAD", "POST"}

// XHTTPRelayAllowedMethod returns true if the given HTTP method is allowed.
// Source: XHTTPRelayFastly-master/src/index.js ALLOWED_METHODS.has
func XHTTPRelayAllowedMethod(method string) bool {
	for _, m := range XHTTPRelayAllowedMethods {
		if m == method {
			return true
		}
	}
	return false
}

// XHTTPRelayNormalizePath normalizes a URL path by removing double slashes
// and trailing slashes. Source: XHTTPRelayFastly-master/src/index.js normalizePath.
func XHTTPRelayNormalizePath(pathname string) string {
	if pathname == "" {
		pathname = "/"
	}
	// collapse double slashes
	for strings.Contains(pathname, "//") {
		pathname = strings.ReplaceAll(pathname, "//", "/")
	}
	if !strings.HasPrefix(pathname, "/") {
		pathname = "/" + pathname
	}
	if len(pathname) > 1 && strings.HasSuffix(pathname, "/") {
		pathname = pathname[:len(pathname)-1]
	}
	return pathname
}

// XHTTPRelayIsAllowedPath checks whether pathname is under publicPath.
// Source: XHTTPRelayFastly-master/src/index.js isAllowedRelayPath.
func XHTTPRelayIsAllowedPath(pathname, publicPath string) bool {
	return pathname == publicPath || strings.HasPrefix(pathname, publicPath+"/")
}

// XHTTPRelayMapPath remaps a public pathname to an upstream relay path.
// Source: XHTTPRelayFastly-master/src/index.js mapPath.
func XHTTPRelayMapPath(pathname, publicPath, relayPath string) string {
	if pathname == publicPath {
		return relayPath
	}
	return relayPath + pathname[len(publicPath):]
}

// XHTTPRelayResponseCacheHeaders returns the fixed no-cache response headers
// that must be set on all relay responses.
// Source: XHTTPRelayFastly-master/src/index.js responseHeaders assignments.
var XHTTPRelayResponseCacheHeaders = map[string]string{
	"Cache-Control":     "no-store, no-cache, must-revalidate, max-age=0",
	"CDN-Cache-Control": "no-store",
}

// XHTTPRelayStrippedResponseHeaders lists headers removed from upstream responses.
// Source: XHTTPRelayFastly-master/src/index.js for-loop strip logic.
var XHTTPRelayStrippedResponseHeaders = []string{"transfer-encoding", "connection"}
