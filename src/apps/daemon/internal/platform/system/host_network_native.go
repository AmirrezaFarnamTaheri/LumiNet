package system

import "context"

func nativeHostNetworkOps() hostNetworkOps {
	mgr := GetTunRouterManager()
	return hostNetworkOps{
		getProxy: GetSystemProxy,
		setProxy: func(ctx context.Context, settings *ProxySettings) error { return SetSystemProxy(ctx, settings) },
		getDNS:   GetDNS,
		setDNS: func(ctx context.Context, iface string, servers []string) error {
			if len(servers) == 0 {
				return ResetDNS(ctx, iface)
			}
			return SetDNS(ctx, iface, servers)
		},
		getNCSI:  GetNCSIConfig,
		setNCSI:  SetNCSIConfig,
		startTun: mgr.startWithLease,
		stopTun:  mgr.stopWithLease,
		tunUp:    mgr.IsRunning,
	}
}
