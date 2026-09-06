package proxyconfig

import (
	"strconv"
)

type UnifiedOutboundDefinition struct {
	Tag           string
	Protocol      string
	Server        string
	ServerPort    uint16
	UUID          string
	TLSSNI        string
	TransportType string
	WsPath        string
}

type MultiFormatCompiler struct{}

func (c *MultiFormatCompiler) CompileSingBox(def *UnifiedOutboundDefinition) string {
	return `{"type":"` + def.Protocol + `","tag":"` + def.Tag + `","server":"` + def.Server + `","server_port":` + strconv.Itoa(int(def.ServerPort)) + `,"uuid":"` + def.UUID + `","tls":{"enabled":true,"server_name":"` + def.TLSSNI + `"},"transport":{"type":"` + def.TransportType + `","path":"` + def.WsPath + `"}}`
}

func (c *MultiFormatCompiler) CompileXray(def *UnifiedOutboundDefinition) string {
	return `{"protocol":"` + def.Protocol + `","tag":"` + def.Tag + `","settings":{"vnext":[{"address":"` + def.Server + `","port":` + strconv.Itoa(int(def.ServerPort)) + `,"users":[{"id":"` + def.UUID + `"}]}]},"streamSettings":{"network":"` + def.TransportType + `","security":"tls","tlsSettings":{"serverName":"` + def.TLSSNI + `"},"wsSettings":{"path":"` + def.WsPath + `"}}}`
}

func (c *MultiFormatCompiler) CompileClash(def *UnifiedOutboundDefinition) string {
	return "- name: \"" + def.Tag + "\"\n  type: " + def.Protocol + "\n  server: " + def.Server + "\n  port: " + strconv.Itoa(int(def.ServerPort)) + "\n  uuid: " + def.UUID + "\n  tls: true\n  servername: " + def.TLSSNI + "\n  network: " + def.TransportType + "\n  ws-opts:\n    path: " + def.WsPath
}
