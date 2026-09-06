package proxy

import proxyconfig "github.com/maybeknott/luminet/internal/networking/proxyconfig"

// parseNipo retains the historical protocol-specific path used by the format
// registry. It intentionally bypasses generic parseProxyURI validation.
func parseNipo(uri string) (*proxyConfig, error) {
	return proxyconfig.ParseNipoDirect(uri)
}

// parseTUIC retains the historical protocol-specific test/caller path.
func parseTUIC(uri string) (*proxyConfig, error) {
	return proxyconfig.ParseTUICDirect(uri)
}
