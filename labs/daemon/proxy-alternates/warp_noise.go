package proxy

import "github.com/maybeknott/luminet/internal/warpnoise"

type WarpNoiseConfig = warpnoise.WarpNoiseConfig
type WarpNoiseInjector = warpnoise.WarpNoiseInjector

func NewWarpNoiseInjector(cfg WarpNoiseConfig) *WarpNoiseInjector {
	return warpnoise.NewWarpNoiseInjector(cfg)
}
