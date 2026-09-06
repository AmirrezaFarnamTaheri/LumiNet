// Package ui implements admin panel models, wireguard obfuscation, and subscription services.
// Ported from: 3ax-ui-main (mtproto/manager.go)
// Target path: server/internal/ui/mtproto_config.go

package ui

import (
	"fmt"
	"strconv"
	"strings"
)

// MTProtoClientSecret represents one active user of an mtproto proxy.
type MTProtoClientSecret struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
	Email  string `json:"email"`
}

// Getters & Setters for MTProtoClientSecret
func (s *MTProtoClientSecret) GetID() string { return s.ID }
func (s *MTProtoClientSecret) SetID(v string) { s.ID = v }

// MTProtoInstance represents the configuration profile for an MTProto daemon instance.
type MTProtoInstance struct {
	ID                    int                   `json:"id"`
	Tag                   string                `json:"tag"`
	Listen                string                `json:"listen"`
	Port                  int                   `json:"port"`
	MultiUser             bool                  `json:"multi_user"`
	Clients               []MTProtoClientSecret `json:"clients"`
	Debug                 bool                  `json:"debug"`
	ProxyProtocolListener bool                  `json:"proxy_protocol_listener"`
	PreferIP              string                `json:"prefer_ip,omitempty"`
	FrontingIP            string                `json:"fronting_ip,omitempty"`
	FrontingPort          int                   `json:"fronting_port,omitempty"`
	RouteThroughXray      bool                  `json:"route_through_xray"`
	XrayRoutePort         int                   `json:"xray_route_port,omitempty"`
}

// Getters & Setters for MTProtoInstance
func (inst *MTProtoInstance) GetID() int { return inst.ID }
func (inst *MTProtoInstance) SetID(v int) { inst.ID = v }

func (inst *MTProtoInstance) BindTo() string {
	listen := inst.Listen
	if listen == "" {
		listen = "0.0.0.0"
	}
	return fmt.Sprintf("%s:%d", listen, inst.Port)
}

// Fingerprint builds a hash of configuration variables to verify changes.
// Maps to upstream fingerprint() in manager.go.
func (inst *MTProtoInstance) Fingerprint() string {
	parts := []string{
		inst.BindTo(),
		strconv.FormatBool(inst.MultiUser),
		strconv.FormatBool(inst.Debug),
		strconv.FormatBool(inst.ProxyProtocolListener),
		inst.PreferIP,
		inst.FrontingIP,
		strconv.Itoa(inst.FrontingPort),
		strconv.FormatBool(inst.RouteThroughXray),
		strconv.Itoa(inst.XrayRoutePort),
	}
	for _, c := range inst.ActiveClients() {
		parts = append(parts, c.ID+"="+c.Secret+"="+c.Email)
	}
	return strings.Join(parts, "|")
}

// ActiveClients returns served clients depending on the backend multi-user support.
func (inst *MTProtoInstance) ActiveClients() []MTProtoClientSecret {
	if inst.MultiUser || len(inst.Clients) <= 1 {
		return inst.Clients
	}
	return inst.Clients[:1]
}
