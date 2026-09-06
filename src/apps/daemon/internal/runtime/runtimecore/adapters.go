package runtimecore

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	system "github.com/maybeknott/luminet/internal/platform/system"
)

func productionFactory(req Request) (engine, error) {
	switch req.Engine {
	case EngineTor:
		eng := newTorEngine(req.SocksPort, req.ControlPort)
		if len(req.Bridges) > 0 || len(req.TransportPlugins) > 0 {
			plugins := make([]system.TorTransportPlugin, len(req.TransportPlugins))
			for i, plugin := range req.TransportPlugins {
				executable, err := resolveTorTransportExecutable(plugin.Executable)
				if err != nil {
					return nil, fmt.Errorf("%w: Tor transport %s: %v", ErrInvalidRequest, plugin.Name, err)
				}
				plugins[i] = system.TorTransportPlugin{Name: plugin.Name, Executable: executable, Args: append([]string(nil), plugin.Args...)}
			}
			eng.ConfigureBridgesWithTransports(req.Bridges, plugins)
		}
		return eng, nil
	case EnginePsiphon:
		eng := newPsiphonEngine(req.SocksPort)
		if req.UpstreamProxy != "" {
			eng.SetUpstreamProxy(req.UpstreamProxy)
		}
		return eng, nil
	case EngineSSTP:
		return newSSTPEngine(req), nil
	case EngineIKEv2:
		return newIKEv2Engine(req), nil
	default:
		return nil, ErrInvalidRequest
	}
}

func productionPreflight(req Request) (Request, error) {
	if req.Engine != EngineTor || len(req.TransportPlugins) == 0 {
		return req, nil
	}
	out := req
	out.TransportPlugins = cloneTorTransportPluginRequests(req.TransportPlugins)
	for i := range out.TransportPlugins {
		resolved, err := resolveTorTransportExecutable(out.TransportPlugins[i].Executable)
		if err != nil {
			return Request{}, fmt.Errorf("%w: Tor transport %s: %v", ErrInvalidRequest, out.TransportPlugins[i].Name, err)
		}
		out.TransportPlugins[i].Executable = resolved
	}
	return out, nil
}

func resolveTorTransportExecutable(name string) (string, error) {
	if path, err := exec.LookPath(name); err == nil {
		if abs, absErr := filepath.Abs(path); absErr == nil {
			return abs, nil
		}
		return path, nil
	}
	for _, candidate := range []string{filepath.Join("bin", "tor", name), filepath.Join(".", "bin", "tor", name)} {
		info, err := os.Stat(candidate)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
			continue
		}
		abs, absErr := filepath.Abs(candidate)
		if absErr == nil {
			return abs, nil
		}
		return candidate, nil
	}
	return "", fmt.Errorf("allow-listed executable %q was not found in PATH or bin/tor", name)
}
