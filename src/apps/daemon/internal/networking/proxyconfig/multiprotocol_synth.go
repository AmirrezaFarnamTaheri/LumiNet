package proxyconfig

import (
	"fmt"
)

type TransportType string

const (
	TransportTcpReality  TransportType = "tcp-reality"
	TransportWebsocket   TransportType = "ws"
	TransportGrpc        TransportType = "grpc"
)

type ProtocolPreset struct {
	ListenPort uint16        `json:"listen_port"`
	ServerUUID string        `json:"server_uuid"`
	SniDest    string        `json:"sni_dest"`
	Transport  TransportType `json:"transport"`
}

type MultiprotocolSynthesizer struct{}

func NewMultiprotocolSynthesizer() *MultiprotocolSynthesizer {
	return &MultiprotocolSynthesizer{}
}

func (s *MultiprotocolSynthesizer) GenerateInboundConfig(preset ProtocolPreset) string {
	return fmt.Sprintf(`{"type":"vless","tag":"in-%s","listen_port":%d,"users":[{"uuid":"%s"}],"tls":{"enabled":true,"server_name":"%s"}}`,
		preset.Transport, preset.ListenPort, preset.ServerUUID, preset.SniDest)
}
