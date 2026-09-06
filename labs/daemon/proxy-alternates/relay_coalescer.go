package proxy

import appsscript "github.com/maybeknott/luminet/internal/relayclient/appsscript"

const (
	MaxProxyRequestBody = appsscript.MaxProxyRequestBody
)

type RelayResponse = appsscript.RelayResponse
type Coalescer = appsscript.Coalescer

var (
	NewCoalescer         = appsscript.NewCoalescer
	NewHTTPClient        = appsscript.NewHTTPClient
	AppsScriptRoundTrip  = appsscript.AppsScriptRoundTrip
)
