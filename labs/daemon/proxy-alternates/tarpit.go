package proxy

import (
	"github.com/maybeknott/luminet/internal/log"
	"github.com/maybeknott/luminet/internal/tarpit"
)

type TarpitServer = tarpit.TarpitServer
type TarpitMetrics = tarpit.TarpitMetrics
type RateLimitedTarpitServer = tarpit.RateLimitedTarpitServer

func GetTarpitServer() *TarpitServer                   { return tarpit.GetTarpitServer() }
func NewTarpitServer(logger *log.Logger) *TarpitServer { return tarpit.NewTarpitServer(logger) }
func NewRateLimitedTarpitServer(logger *log.Logger, maxConns int64) *RateLimitedTarpitServer {
	return tarpit.NewRateLimitedTarpitServer(logger, maxConns)
}
