package proxy

import (
	"github.com/maybeknott/luminet/internal/relayserver"
	"github.com/maybeknott/luminet/internal/relaywire"
)

type TunnelPayload = relaywire.TunnelPayload
type TunnelResponse = relaywire.TunnelResponse
type EvasionRelayServer = relayserver.EvasionRelayServer

func NewEvasionRelayServer(addr string) *EvasionRelayServer {
	return relayserver.NewEvasionRelayServer(addr)
}
func StartEvasionRelayServer(addr string) error { return relayserver.StartEvasionRelayServer(addr) }
func StartEvasionRelayServerWithDecoy(addr, decoyTarget string, secretPaths []string, blockedCIDRs []string) error {
	return relayserver.StartEvasionRelayServerWithDecoy(addr, decoyTarget, secretPaths, blockedCIDRs)
}
