package proxy

import (
	"github.com/maybeknott/luminet/internal/relayserver"
	"time"
)

type RealityVerifier = relayserver.RealityVerifier
type ReplayConn = relayserver.ReplayConn

func NewRealityVerifier(authKey []byte, decoyAddress string) (*RealityVerifier, error) {
	return relayserver.NewRealityVerifier(authKey, decoyAddress)
}
func NewRealityVerifierWithParams(authKey []byte, decoyAddress string, privateKey []byte, shortIDs []string, maxTimeDiff time.Duration) (*RealityVerifier, error) {
	return relayserver.NewRealityVerifierWithParams(authKey, decoyAddress, privateKey, shortIDs, maxTimeDiff)
}
