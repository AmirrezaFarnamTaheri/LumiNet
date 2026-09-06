package proxy

import (
	"github.com/maybeknott/luminet/internal/relayserver"
	"net"
)

type FallbackProxy = relayserver.FallbackProxy

func NewFallbackProxy(bindAddr, localTarget, decoyTarget string, secretPaths []string) *FallbackProxy {
	return relayserver.NewFallbackProxy(bindAddr, localTarget, decoyTarget, secretPaths)
}

var _ net.Addr
