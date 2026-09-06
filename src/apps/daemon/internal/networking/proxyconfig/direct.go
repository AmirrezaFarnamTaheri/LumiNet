package proxyconfig

// ParseNipoDirect preserves the historical direct Nipo parser semantics without
// routing through ParseProxyURI's generic suspicious-input validation.
func ParseNipoDirect(uri string) (*ProxyConfig, error) {
	return parseNipo(uri)
}

// ParseTUICDirect preserves the historical direct TUIC parser semantics used
// by compatibility tests and protocol-specific callers.
func ParseTUICDirect(uri string) (*ProxyConfig, error) {
	return parseTUIC(uri)
}
