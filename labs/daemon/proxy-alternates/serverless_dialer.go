package proxy

import (
	"net"

	serverless "github.com/maybeknott/luminet/internal/relayclient/serverless"
)

// ServerlessDialer is retained for compatibility; implementation lives in relayclient/serverless.
type ServerlessDialer = serverless.ServerlessDialer

func NewServerlessDialer(relayURL string) *ServerlessDialer {
	return serverless.NewServerlessDialer(relayURL)
}

func NewHttpServerlessConn(relayURL, realDst string) net.Conn {
	return serverless.NewHttpServerlessConn(relayURL, realDst)
}

// serverlessConn preserves the historical private proxy seam used by wstunnel.go.
type serverlessConn = serverless.WebSocketConn
