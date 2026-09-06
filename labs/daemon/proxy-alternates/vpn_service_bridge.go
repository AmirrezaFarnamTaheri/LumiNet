package proxy

import "github.com/maybeknott/luminet/internal/vpnstate"

type VPNState = vpnstate.VPNState
type VPNServiceBridge = vpnstate.VPNServiceBridge

func NewVPNServiceBridge() *VPNServiceBridge { return vpnstate.NewVPNServiceBridge() }
