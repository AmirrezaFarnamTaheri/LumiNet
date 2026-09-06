package proxy

import (
	"net"

	"github.com/maybeknott/luminet/internal/tlsfragment"
)

type FragmentationStrategy = tlsfragment.FragmentationStrategy

const (
	StrategyNone          = tlsfragment.StrategyNone
	StrategySniSplit      = tlsfragment.StrategySniSplit
	StrategyHalf          = tlsfragment.StrategyHalf
	StrategyMulti         = tlsfragment.StrategyMulti
	StrategyTlsRecordFrag = tlsfragment.StrategyTlsRecordFrag
)

type UTLSFragmentConfig = tlsfragment.UTLSFragmentConfig

func WrapUTLSFragmentConn(conn net.Conn, cfg UTLSFragmentConfig) net.Conn {
	return tlsfragment.WrapUTLSFragmentConn(conn, cfg)
}
