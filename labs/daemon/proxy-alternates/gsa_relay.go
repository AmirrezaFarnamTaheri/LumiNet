package proxy

import gsa "github.com/maybeknott/luminet/internal/relayclient/gsa"

type GsaTunnelConn = gsa.GsaTunnelConn

func NewGsaTunnelConn(scriptURL, authKey, realDst string) *GsaTunnelConn {
	return gsa.NewGsaTunnelConn(scriptURL, authKey, realDst)
}
