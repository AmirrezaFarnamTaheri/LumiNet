package proxy

import proxyconfig "github.com/maybeknott/luminet/internal/networking/proxyconfig"

// Package-private aliases keep proxy implementation files concise without
// re-exporting proxyconfig as a second caller-facing interface.
type proxyProtocol = proxyconfig.ProxyProtocol
type proxyConfig = proxyconfig.ProxyConfig

const (
	protocolVMess        = proxyconfig.ProtocolVMess
	protocolVLESS        = proxyconfig.ProtocolVLESS
	protocolTrojan       = proxyconfig.ProtocolTrojan
	protocolShadowsocks  = proxyconfig.ProtocolShadowsocks
	protocolShadowsocksR = proxyconfig.ProtocolShadowsocksR
	protocolSOCKS5       = proxyconfig.ProtocolSOCKS5
	protocolHTTP         = proxyconfig.ProtocolHTTP
	protocolHysteria2    = proxyconfig.ProtocolHysteria2
	protocolTUIC         = proxyconfig.ProtocolTUIC
	protocolNaive        = proxyconfig.ProtocolNaive
	protocolWireGuard    = proxyconfig.ProtocolWireGuard
	protocolAmneziaWG    = proxyconfig.ProtocolAmneziaWG
	protocolSingBox      = proxyconfig.ProtocolSingBox
	protocolKCP          = proxyconfig.ProtocolKCP
	protocolAnyTLS       = proxyconfig.ProtocolAnyTLS
	protocolJuicity      = proxyconfig.ProtocolJuicity
	protocolNipo         = proxyconfig.ProtocolNipo
	protocolDNSTT        = proxyconfig.ProtocolDNSTT
)

var (
	isSuspicious                 = proxyconfig.IsSuspicious
	parseProxyURI                = proxyconfig.ParseProxyURI
	parseProxyList               = proxyconfig.ParseProxyList
	sanitizeAndDedupe            = proxyconfig.SanitizeAndDedupe
	extractRealityParams         = proxyconfig.ExtractRealityParams
	decodeFinalMask              = proxyconfig.DecodeFinalMask
	buildXrayTLSSettings         = proxyconfig.BuildXrayTLSSettings
	buildXrayXHTTPSettings       = proxyconfig.BuildXrayXHTTPSettings
	canonicalXHTTPTransport      = proxyconfig.CanonicalXHTTPTransport
	parseHysteria2PortHopping    = proxyconfig.ParseHysteria2PortHopping
	buildXrayHysteria2Settings   = proxyconfig.BuildXrayHysteria2Settings
	validateSingBoxCompatibility = proxyconfig.ValidateSingBoxCompatibility
	validateXrayCompatibility    = proxyconfig.ValidateXrayCompatibility
)
