package system

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	maxTorBridges          = 64
	maxTorTransportPlugins = 8
	maxTorTransportArgs    = 16
	maxTorDirectiveBytes   = 4096
	maxTorTokenBytes       = 1024
)

var torTransportNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// TorTransportPlugin declares one executable Tor pluggable transport. LumiNet
// writes tokens directly to torrc and never invokes a shell; to keep the torrc
// grammar unambiguous, names, executable paths, and arguments are validated as
// single tokens with no whitespace or control characters.
type TorTransportPlugin struct {
	Name       string
	Executable string
	Args       []string
}

// TorConfigBuilder generates a torrc configuration string. Validation errors
// are accumulated during construction and returned by BuildValidated so unsafe
// dynamic bridge/plugin material can never become an authoritative torrc.
type TorConfigBuilder struct {
	lines []string
	err   error
}

func NewTorConfigBuilder() *TorConfigBuilder { return &TorConfigBuilder{} }

func (b *TorConfigBuilder) fail(err error) *TorConfigBuilder {
	if b.err == nil {
		b.err = err
	}
	return b
}

func (b *TorConfigBuilder) add(line string) *TorConfigBuilder {
	if b.err != nil {
		return b
	}
	if len(line) == 0 || len(line) > maxTorDirectiveBytes || strings.ContainsAny(line, "\r\n\x00") {
		return b.fail(fmt.Errorf("tor_config: invalid directive length/content"))
	}
	b.lines = append(b.lines, line)
	return b
}

func (b *TorConfigBuilder) SocksPort(port int, isolateDestAddr, isolateDestPort bool) *TorConfigBuilder {
	flags := []string{}
	if isolateDestAddr {
		flags = append(flags, "IsolateDestAddr")
	}
	if isolateDestPort {
		flags = append(flags, "IsolateDestPort")
	}
	if len(flags) == 0 {
		return b.add(fmt.Sprintf("SocksPort 127.0.0.1:%d", port))
	}
	return b.add(fmt.Sprintf("SocksPort 127.0.0.1:%d %s", port, strings.Join(flags, " ")))
}

func (b *TorConfigBuilder) ControlPort(port int) *TorConfigBuilder {
	return b.add(fmt.Sprintf("ControlPort 127.0.0.1:%d", port))
}

func (b *TorConfigBuilder) DataDirectory(path string) *TorConfigBuilder {
	token, err := formatTorToken("data directory", path)
	if err != nil {
		return b.fail(err)
	}
	return b.add(fmt.Sprintf("DataDirectory %s", token))
}

func (b *TorConfigBuilder) CookieAuth(cookiePath string) *TorConfigBuilder {
	token, err := formatTorToken("cookie path", cookiePath)
	if err != nil {
		return b.fail(err)
	}
	b.add("CookieAuthentication 1")
	return b.add(fmt.Sprintf("CookieAuthFile %s", token))
}

func (b *TorConfigBuilder) ConnectionPadding(reduced bool) *TorConfigBuilder {
	if reduced {
		return b.add("ReducedConnectionPadding 1")
	}
	return b.add("ConnectionPadding 1")
}

func (b *TorConfigBuilder) CircuitPadding(enabled, reduced bool) *TorConfigBuilder {
	b.add(fmt.Sprintf("CircuitPadding %d", boolToInt(enabled)))
	if reduced {
		b.add("ReducedCircuitPadding 1")
	}
	return b
}

func (b *TorConfigBuilder) VirtualAddrNetwork() *TorConfigBuilder {
	b.add("VirtualAddrNetwork 10.192.0.0/10")
	return b.add("AutomapHostsOnResolve 1")
}

func (b *TorConfigBuilder) DormantPolicy() *TorConfigBuilder {
	b.add("DormantClientTimeout 10 minutes")
	return b.add("DormantCanceledByStartup 1")
}

func (b *TorConfigBuilder) ReachableAddresses(ports string) *TorConfigBuilder {
	if ports == "" {
		ports = "*:80,*:443"
	}
	if len(ports) > maxTorTokenBytes || strings.ContainsAny(ports, "\r\n\x00") {
		return b.fail(fmt.Errorf("tor_config: invalid reachable-address expression"))
	}
	return b.add(fmt.Sprintf("ReachableAddresses %s", ports))
}

func (b *TorConfigBuilder) HTTPTunnelPort(port int, isolateDestAddr, isolateDestPort bool) *TorConfigBuilder {
	flags := []string{}
	if isolateDestAddr {
		flags = append(flags, "IsolateDestAddr")
	}
	if isolateDestPort {
		flags = append(flags, "IsolateDestPort")
	}
	if len(flags) == 0 {
		return b.add(fmt.Sprintf("HTTPTunnelPort 127.0.0.1:%d", port))
	}
	return b.add(fmt.Sprintf("HTTPTunnelPort 127.0.0.1:%d %s", port, strings.Join(flags, " ")))
}

func (b *TorConfigBuilder) IPv6Prefs(preferIpv6, disableIpv4 bool) *TorConfigBuilder {
	if preferIpv6 || disableIpv4 {
		b.add("IPv6Traffic 1")
	}
	if preferIpv6 {
		b.add("PreferIPv6 1")
	}
	if disableIpv4 {
		b.add("NoIPv4Traffic 1")
	}
	return b
}

func (b *TorConfigBuilder) KeepAliveIsolateSOCKSAuth() *TorConfigBuilder {
	return b.add("KeepAliveIsolateSOCKSAuth 1")
}

// AvoidDiskWrites asks Tor to minimize disk writes. The enabled value is 1.
func (b *TorConfigBuilder) AvoidDiskWrites() *TorConfigBuilder {
	return b.add("AvoidDiskWrites 1")
}

func (b *TorConfigBuilder) LogNoticeStdout() *TorConfigBuilder {
	return b.add("Log notice stdout")
}

// Bridges is the backward-compatible obfs4 helper.
func (b *TorConfigBuilder) Bridges(bridges []string, obfs4ProxyPath string) *TorConfigBuilder {
	plugins := []TorTransportPlugin{}
	if strings.TrimSpace(obfs4ProxyPath) != "" {
		plugins = append(plugins, TorTransportPlugin{Name: "obfs4", Executable: obfs4ProxyPath})
	}
	return b.BridgesWithTransports(bridges, plugins)
}

// BridgesWithTransports configures bridges and any required client pluggable
// transports (for example obfs4, snowflake, or webtunnel). It deliberately
// models the transport as data rather than hard-coding an external binary.
func (b *TorConfigBuilder) BridgesWithTransports(bridges []string, plugins []TorTransportPlugin) *TorConfigBuilder {
	if len(bridges) == 0 {
		if len(plugins) > 0 {
			return b.fail(fmt.Errorf("tor_config: transport plugins require at least one bridge"))
		}
		return b
	}
	if len(bridges) > maxTorBridges {
		return b.fail(fmt.Errorf("tor_config: too many bridges: %d > %d", len(bridges), maxTorBridges))
	}
	if len(plugins) > maxTorTransportPlugins {
		return b.fail(fmt.Errorf("tor_config: too many transport plugins: %d > %d", len(plugins), maxTorTransportPlugins))
	}

	seen := make(map[string]struct{}, len(plugins))
	b.add("UseBridges 1")
	for _, plugin := range plugins {
		name := strings.TrimSpace(plugin.Name)
		if !torTransportNamePattern.MatchString(name) {
			return b.fail(fmt.Errorf("tor_config: invalid transport name %q", plugin.Name))
		}
		if _, exists := seen[name]; exists {
			return b.fail(fmt.Errorf("tor_config: duplicate transport %q", name))
		}
		seen[name] = struct{}{}
		executable, err := formatTorToken("transport executable", plugin.Executable)
		if err != nil {
			return b.fail(err)
		}
		if len(plugin.Args) > maxTorTransportArgs {
			return b.fail(fmt.Errorf("tor_config: too many args for transport %q", name))
		}
		tokens := []string{"ClientTransportPlugin", name, "exec", executable}
		for _, arg := range plugin.Args {
			token, err := formatTorToken("transport argument", arg)
			if err != nil {
				return b.fail(err)
			}
			tokens = append(tokens, token)
		}
		b.add(strings.Join(tokens, " "))
	}
	for _, bridge := range bridges {
		bridge = strings.TrimSpace(bridge)
		if bridge == "" || len(bridge) > maxTorDirectiveBytes-len("Bridge ") || strings.ContainsAny(bridge, "\r\n\x00") {
			return b.fail(fmt.Errorf("tor_config: invalid bridge line"))
		}
		b.add("Bridge " + bridge)
	}
	return b
}

// ExtraLine remains available only for static/trusted call sites. Dynamic
// material should use typed methods above; CR/LF/NUL injection is rejected.
func (b *TorConfigBuilder) ExtraLine(line string) *TorConfigBuilder { return b.add(line) }

// BuildValidated returns authoritative torrc text only when every dynamic
// directive passed validation.
func (b *TorConfigBuilder) BuildValidated() (string, error) {
	if b.err != nil {
		return "", b.err
	}
	return strings.Join(b.lines, "\n"), nil
}

// Build is retained for trusted static callers. Invalid dynamic construction
// returns an empty string; authoritative writers must use BuildValidated.
func (b *TorConfigBuilder) Build() string {
	v, err := b.BuildValidated()
	if err != nil {
		return ""
	}
	return v
}

func (b *TorConfigBuilder) Lines() []string { return append([]string(nil), b.lines...) }

func formatTorToken(kind, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxTorTokenBytes || strings.ContainsAny(value, "\r\n\x00") {
		return "", fmt.Errorf("tor_config: invalid %s", kind)
	}
	if strings.IndexFunc(value, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '"' || r == '\\' || r == '#'
	}) >= 0 {
		return strconv.Quote(value), nil
	}
	return value, nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
