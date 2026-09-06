package proxy

import proxyconfig "github.com/maybeknott/luminet/internal/proxyconfig"

// Re-export canonical proxy configuration parsing so existing callers keep
// compiling while the implementation has one owner.
type ProxyProtocol = proxyconfig.ProxyProtocol
type ProxyConfig = proxyconfig.ProxyConfig

const (
	ProtocolVMess        = proxyconfig.ProtocolVMess
	ProtocolVLESS        = proxyconfig.ProtocolVLESS
	ProtocolTrojan       = proxyconfig.ProtocolTrojan
	ProtocolShadowsocks  = proxyconfig.ProtocolShadowsocks
	ProtocolShadowsocksR = proxyconfig.ProtocolShadowsocksR
	ProtocolSOCKS5       = proxyconfig.ProtocolSOCKS5
	ProtocolHTTP         = proxyconfig.ProtocolHTTP
	ProtocolHysteria2    = proxyconfig.ProtocolHysteria2
	ProtocolTUIC         = proxyconfig.ProtocolTUIC
	ProtocolNaive        = proxyconfig.ProtocolNaive
	ProtocolWireGuard    = proxyconfig.ProtocolWireGuard
	ProtocolAmneziaWG    = proxyconfig.ProtocolAmneziaWG
	ProtocolSingBox      = proxyconfig.ProtocolSingBox
	ProtocolKCP          = proxyconfig.ProtocolKCP
	ProtocolAnyTLS       = proxyconfig.ProtocolAnyTLS
	ProtocolJuicity      = proxyconfig.ProtocolJuicity
	ProtocolNipo         = proxyconfig.ProtocolNipo
	ProtocolDNSTT        = proxyconfig.ProtocolDNSTT
)

var (
	IsSuspicious         = proxyconfig.IsSuspicious
	ParseProxyURI        = proxyconfig.ParseProxyURI
	ParseProxyList       = proxyconfig.ParseProxyList
	SanitizeAndDedupe    = proxyconfig.SanitizeAndDedupe
	ExtractRealityParams = proxyconfig.ExtractRealityParams
)
