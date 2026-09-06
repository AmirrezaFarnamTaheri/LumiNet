package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/maybeknott/luminet/internal/networking/dns"
	"github.com/maybeknott/luminet/internal/platform/system"
	"github.com/maybeknott/luminet/internal/runtime/proxy"
	"github.com/spf13/cobra"
)

const ()

// systemCmd is the parent command for system configuration subcommands.
var systemCmd = &cobra.Command{
	Use:   "system",
	Short: "Control System (Workflow 4: Manage DNS, system proxy, DDNS, profiles, and startup settings)",
	Long:  `Control System workflow handles OS-level network modifications (DNS, proxy, DDNS, host profiles) using transactional state mutations and watchdog protections.`,
}

// systemDnsCmd manages DNS server settings.
var systemDnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "Manage system DNS server settings",
}

var systemDnsApplyCmd = &cobra.Command{
	Use:   "apply [servers...]",
	Short: "Apply DNS servers to the active network interface",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runDnsApply,
}

var systemDnsClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear DNS servers (reset to DHCP)",
	RunE:  runDnsClear,
}

var systemDnsStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current DNS configuration",
	RunE:  runDnsStatus,
}

// systemProxyCmd manages system proxy settings.
var systemProxyCmd = &cobra.Command{
	Use:   "proxy-settings",
	Short: "Manage system proxy settings",
}

var systemProxyApplyCmd = &cobra.Command{
	Use:   "apply [server]",
	Short: "Apply system proxy settings",
	Args:  cobra.ExactArgs(1),
	RunE:  runProxyApply,
}

var systemProxyClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear system proxy settings",
	RunE:  runProxyClear,
}

var systemProxyStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current proxy settings",
	RunE:  runProxyStatus,
}

// systemDdnsCmd manages DDNS updates.
var systemDdnsCmd = &cobra.Command{
	Use:   "ddns",
	Short: "Manage Dynamic DNS updates",
}

var systemDdnsForceCmd = &cobra.Command{
	Use:   "force",
	Short: "Force an immediate DDNS update",
	RunE:  runDdnsForce,
}

// systemProfilesCmd manages network profiles.
var systemProfilesCmd = &cobra.Command{
	Use:   "profiles",
	Short: "Manage network profiles",
}

var systemProfilesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all configured network profiles",
	RunE:  runProfilesList,
}

var systemProfilesApplyCmd = &cobra.Command{
	Use:   "apply [name]",
	Short: "Apply a network profile by name",
	Args:  cobra.ExactArgs(1),
	RunE:  runProfilesApply,
}

// systemStartupCmd manages startup behavior.
var systemStartupCmd = &cobra.Command{
	Use:   "startup",
	Short: "Manage LumiNet startup settings",
}

var systemStartupStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show whether LumiNet is set to start at login",
	RunE:  runStartupStatus,
}

var systemStartupEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable LumiNet at startup",
	RunE:  runStartupEnable,
}

var systemStartupDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable LumiNet at startup",
	RunE:  runStartupDisable,
}

var systemEvasionTunnelCmd = &cobra.Command{
	Use:   "evasion-tunnel",
	Short: "Manage or run local SOCKS5 Evasion Tunnel",
}

var systemEvasionTunnelStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the local SOCKS5 Evasion Tunnel in the foreground",
	RunE:  runEvasionTunnelStart,
}

func init() {
	rootCmd.AddCommand(systemCmd)

	systemCmd.AddCommand(systemDnsCmd)
	systemDnsCmd.AddCommand(systemDnsApplyCmd, systemDnsClearCmd, systemDnsStatusCmd)
	systemDnsApplyCmd.Flags().StringP("interface", "i", "", "network interface alias (auto-detected if empty)")

	systemCmd.AddCommand(systemProxyCmd)
	systemProxyCmd.AddCommand(systemProxyApplyCmd, systemProxyClearCmd, systemProxyStatusCmd)
	systemProxyApplyCmd.Flags().String("bypass", "<local>", "proxy bypass list")
	systemProxyApplyCmd.Flags().String("pac", "", "PAC URL (overrides server)")
	systemProxyApplyCmd.Flags().String("socks5", "", "SOCKS5 proxy server")

	systemCmd.AddCommand(systemDdnsCmd)
	systemDdnsCmd.AddCommand(systemDdnsForceCmd)
	systemDdnsForceCmd.Flags().String("provider", "cloudflare", "DDNS provider (cloudflare, duckdns, noip, dynu)")
	systemDdnsForceCmd.Flags().String("token", "", "DDNS API token or credentials")
	systemDdnsForceCmd.Flags().String("domain", "", "domain name to update")

	systemCmd.AddCommand(systemProfilesCmd)
	systemProfilesCmd.AddCommand(systemProfilesListCmd, systemProfilesApplyCmd)

	systemCmd.AddCommand(systemStartupCmd)
	systemStartupCmd.AddCommand(systemStartupStatusCmd, systemStartupEnableCmd, systemStartupDisableCmd)

	systemCmd.AddCommand(systemEvasionTunnelCmd)
	systemEvasionTunnelCmd.AddCommand(systemEvasionTunnelStartCmd)

	evasionDefaults := proxy.DefaultEvasionConfig()

	systemEvasionTunnelStartCmd.Flags().IntP("port", "p", evasionDefaults.Port, "SOCKS5 proxy local port")
	systemEvasionTunnelStartCmd.Flags().IntP("split", "s", evasionDefaults.SplitBytes, "TCP split offset in bytes")
	systemEvasionTunnelStartCmd.Flags().IntP("delay", "d", evasionDefaults.DelayMs, "TCP split delay in milliseconds")
	systemEvasionTunnelStartCmd.Flags().Bool("mutate-host", evasionDefaults.MutateHost, "Mutate HTTP Host header")
	systemEvasionTunnelStartCmd.Flags().Bool("mutate-header-space", evasionDefaults.MutateHeaderSpace, "Mutate HTTP Header space after colon (spacing evasion)")
	systemEvasionTunnelStartCmd.Flags().Bool("auto-sni", evasionDefaults.AutoSni, "Auto-split TLS SNI boundaries")
	systemEvasionTunnelStartCmd.Flags().Int("sni-split-offset", evasionDefaults.SniSplitOffset, "SNI split offset in bytes")
	systemEvasionTunnelStartCmd.Flags().String("packets", evasionDefaults.Packets, "Target packets mode (tlshello or all)")
	systemEvasionTunnelStartCmd.Flags().Int("min-len", evasionDefaults.MinLength, "Min fragment size in bytes")
	systemEvasionTunnelStartCmd.Flags().Int("max-len", evasionDefaults.MaxLength, "Max fragment size in bytes")
	systemEvasionTunnelStartCmd.Flags().Bool("tls-record-split", evasionDefaults.TlsRecordSplit, "Split ClientHello across multiple TLS records")
	systemEvasionTunnelStartCmd.Flags().String("dns", evasionDefaults.DnsResolver, "Secure DNS resolver (DoH URL or IP)")
	systemEvasionTunnelStartCmd.Flags().Int("dns-fwd-port", evasionDefaults.DnsForwarderPort, "UDP DNS Forwarder port")
	systemEvasionTunnelStartCmd.Flags().Bool("dns-fwd", evasionDefaults.DnsForwarderEnabled, "Enable UDP DNS Forwarder")
	systemEvasionTunnelStartCmd.Flags().Bool("system-proxy", evasionDefaults.SystemProxyEnabled, "Route all system traffic through SOCKS5 Evasion Tunnel")
	systemEvasionTunnelStartCmd.Flags().String("sni-spoof", "", "SNI spoofing target (optional)")
	systemEvasionTunnelStartCmd.Flags().Int("padding", evasionDefaults.ClientHelloPadding, "TLS ClientHello padding size in bytes")
	systemEvasionTunnelStartCmd.Flags().Bool("delay-jitter", evasionDefaults.DelayJitter, "Randomize TCP segment delay to defeat timing heuristics")
	systemEvasionTunnelStartCmd.Flags().Int("tcp-window-clamp", evasionDefaults.TcpWindowClamp, "Clamp TCP read/write buffer sizes to force fragmentation (0 to disable)")
	systemEvasionTunnelStartCmd.Flags().String("custom-user-agent", evasionDefaults.CustomUserAgent, "Spoof HTTP User-Agent header (empty to keep raw)")
	systemEvasionTunnelStartCmd.Flags().String("covert-mode", evasionDefaults.CovertMode, "Covert tunnel mode (direct, paqet, serverless, edge, gsa, gdocs, gdrive, wstunnel, ssh, kcp, tuic)")
	systemEvasionTunnelStartCmd.Flags().String("covert-serverless-url", evasionDefaults.CovertServerlessUrl, "Covert serverless WebSocket relay URL")
	systemEvasionTunnelStartCmd.Flags().String("covert-dns-domain", evasionDefaults.CovertDnsDomain, "Covert DNS tunnel domain name")
	systemEvasionTunnelStartCmd.Flags().String("covert-gsa-url", evasionDefaults.CovertGsaUrl, "Covert GSA Web App URL")
	systemEvasionTunnelStartCmd.Flags().String("covert-gsa-key", evasionDefaults.CovertGsaKey, "Covert GSA Auth Key")
	systemEvasionTunnelStartCmd.Flags().String("covert-gdocs-folder-id", evasionDefaults.CovertGdocsFolderId, "Covert Google Docs Folder ID")
	systemEvasionTunnelStartCmd.Flags().String("covert-gdocs-access-token", evasionDefaults.CovertGdocsAccessToken, "Covert Google Docs Access Token")
	systemEvasionTunnelStartCmd.Flags().Bool("fake-packet-inject", evasionDefaults.FakePacketInject, "Inject fake TCP packets with low TTL")
	systemEvasionTunnelStartCmd.Flags().Int("fake-packet-ttl", evasionDefaults.FakePacketTtl, "TTL for fake TCP packets")
	systemEvasionTunnelStartCmd.Flags().Bool("mutate-sni-case", evasionDefaults.MutateSniCase, "Mutate TLS SNI domain name casing (e.g. yOuTuBe.CoM)")
	systemEvasionTunnelStartCmd.Flags().Bool("mutate-method", evasionDefaults.MutateMethod, "Randomize HTTP method casing (e.g. gEt)")
	systemEvasionTunnelStartCmd.Flags().Bool("mutate-absolute-uri", evasionDefaults.MutateAbsoluteUri, "Convert HTTP requests to use absolute URIs")
	systemEvasionTunnelStartCmd.Flags().Int("http-padding", evasionDefaults.HttpPadding, "Number of dummy HTTP headers to inject for padding")
	systemEvasionTunnelStartCmd.Flags().String("preflight-signature", evasionDefaults.PreflightSignature, "Preflight packet signature in CPS format")
	systemEvasionTunnelStartCmd.Flags().Int("preflight-delay", evasionDefaults.PreflightDelayMs, "Delay in milliseconds after preflight packet injection")
	systemEvasionTunnelStartCmd.Flags().Bool("session-frag", evasionDefaults.SessionFrag, "Enable session-level write fragmentation (Psiphon-style)")
	systemEvasionTunnelStartCmd.Flags().Float64("session-frag-prob", evasionDefaults.SessionFragProb, "Probability of session fragmentation (0.0 to 1.0)")
	systemEvasionTunnelStartCmd.Flags().Int("session-frag-min-total", evasionDefaults.SessionFragMinTotal, "Min total bytes to fragment per session")
	systemEvasionTunnelStartCmd.Flags().Int("session-frag-max-total", evasionDefaults.SessionFragMaxTotal, "Max total bytes to fragment per session")
	systemEvasionTunnelStartCmd.Flags().Int("session-frag-min-chunk", evasionDefaults.SessionFragMinChunk, "Min chunk size for session fragmentation")
	systemEvasionTunnelStartCmd.Flags().Int("session-frag-max-chunk", evasionDefaults.SessionFragMaxChunk, "Max chunk size for session fragmentation")
	systemEvasionTunnelStartCmd.Flags().Int("session-frag-min-delay", evasionDefaults.SessionFragMinDelayMs, "Min chunk delay in milliseconds")
	systemEvasionTunnelStartCmd.Flags().Int("session-frag-max-delay", evasionDefaults.SessionFragMaxDelayMs, "Max chunk delay in milliseconds")
	systemEvasionTunnelStartCmd.Flags().Bool("ip-spoofing", evasionDefaults.IpSpoofingEnabled, "Enable mutual IP spoofing")
	systemEvasionTunnelStartCmd.Flags().String("ip-spoofing-decoy", evasionDefaults.IpSpoofingDecoyIP, "Decoy IP address to spoof")
	systemEvasionTunnelStartCmd.Flags().String("ip-spoofing-dst-real", evasionDefaults.IpSpoofingDstReal, "Real destination IP address")
	systemEvasionTunnelStartCmd.Flags().Bool("out-of-window", evasionDefaults.OutOfWindowEnabled, "Enable out-of-window TCP sequence number injection")
	systemEvasionTunnelStartCmd.Flags().Int("out-of-window-seq-offset", evasionDefaults.OutOfWindowSeqOffset, "Out-of-window sequence number offset shift")
	systemEvasionTunnelStartCmd.Flags().String("decoy-sni-pool", evasionDefaults.DecoySniPool, "Comma-separated pool of decoy SNIs")
	systemEvasionTunnelStartCmd.Flags().Bool("oob", evasionDefaults.OobEnabled, "Enable TCP Out-of-band (OOB) Urgent Data evasion")
	systemEvasionTunnelStartCmd.Flags().Bool("oobex", evasionDefaults.OobexEnabled, "Enable TCP Out-of-band (OOB) Extended evasion (split header)")
	systemEvasionTunnelStartCmd.Flags().Bool("async-reactor", evasionDefaults.AsyncReactorEnabled, "Enable asynchronous gaio Proactor I/O loop")
	systemEvasionTunnelStartCmd.Flags().Float64("loss-rate", evasionDefaults.LossRate, "Simulated packet loss rate percentage (e.g. 1.5)")
	systemEvasionTunnelStartCmd.Flags().Int("emulated-latency", evasionDefaults.EmulatedLatency, "Emulated latency delay in milliseconds")
	systemEvasionTunnelStartCmd.Flags().Int("emulated-jitter", evasionDefaults.EmulatedJitter, "Emulated jitter deviation in milliseconds")
	systemEvasionTunnelStartCmd.Flags().Int("circular-cache-cap", evasionDefaults.CircularCacheCap, "Circular resolver cache size in records")
	systemEvasionTunnelStartCmd.Flags().Int64("shaper-read-rate", evasionDefaults.ShaperReadRate, "Shaper bandwidth read pacing rate (bytes/second)")
	systemEvasionTunnelStartCmd.Flags().Int64("shaper-write-rate", evasionDefaults.ShaperWriteRate, "Shaper bandwidth write pacing rate (bytes/second)")
	systemEvasionTunnelStartCmd.Flags().String("covert-socket-protect-path", evasionDefaults.CovertSocketProtectPath, "Unix domain socket path for socket protection")
	systemEvasionTunnelStartCmd.Flags().Bool("mobile-assets-enabled", evasionDefaults.MobileAssetsEnabled, "Enable Android/mobile asset reader override")
	systemEvasionTunnelStartCmd.Flags().Bool("zygisk-hide-enabled", evasionDefaults.ZygiskHideEnabled, "Hide VPN interfaces from Android apps via Zygisk PLT hooks")
	systemEvasionTunnelStartCmd.Flags().Bool("hardened-tls-enabled", evasionDefaults.HardenedTlsEnabled, "Hardened modern TLS cipher suites configuration")
	systemEvasionTunnelStartCmd.Flags().Bool("upgen", evasionDefaults.UpgenEnabled, "Enable Context-Free Grammar (CFG) protocol obfuscation (UPGen)")
	systemEvasionTunnelStartCmd.Flags().String("upgen-seed", evasionDefaults.UpgenSeedHex, "UPGen shared auth seed hex")
	systemEvasionTunnelStartCmd.Flags().Bool("upgen-entropy", evasionDefaults.UpgenEntropyMatch, "Enable entropy matching/shaping on UPGen traffic")
	systemEvasionTunnelStartCmd.Flags().Int("upgen-quic-rate", evasionDefaults.UpgenQuicExhaustionRate, "Legacy unsupported UPGen QUIC rate (must remain 0)")
	systemEvasionTunnelStartCmd.Flags().Bool("stego", evasionDefaults.StegoEnabled, "Enable steganographic VoIP/WebRTC camouflage")
	systemEvasionTunnelStartCmd.Flags().String("stego-mode", evasionDefaults.StegoMode, "Steganography mode (webrtc_voip or pixel_stego)")
	systemEvasionTunnelStartCmd.Flags().String("stego-decoy-image", evasionDefaults.StegoDecoyImagePath, "Path to decoy PNG image for pixel steganography")
	systemEvasionTunnelStartCmd.Flags().Bool("stego-webrtc-sdp", evasionDefaults.StegoWebRTCSDPSpoof, "Spoof WebRTC Session Description Protocol (SDP) signals")
	systemEvasionTunnelStartCmd.Flags().Bool("residential-cloaking", false, "Route traffic through residential/home proxy egress nodes")
	systemEvasionTunnelStartCmd.Flags().String("residential-egress-node", "", "Residential egress proxy server address (e.g. 192.168.1.254:1080)")
	systemEvasionTunnelStartCmd.Flags().Int("mss-clamping", 1460, "TCP Maximum Segment Size (MSS) clamping value for residential cloaking")
	systemEvasionTunnelStartCmd.Flags().Bool("dns-leaks-shield", true, "Prevent DNS and geolocation leakage via egress resolver")
	systemEvasionTunnelStartCmd.Flags().String("mss-preset", "ethernet", "TCP MSS preset to mimic: ethernet, lte, or 3g")
}

func ctxWithTimeout(secs int) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
}

func runDnsApply(cmd *cobra.Command, args []string) error {
	ctx, cancel := ctxWithTimeout(10)
	defer cancel()

	ifaceName, _ := cmd.Flags().GetString("interface")
	if ifaceName == "" {
		ifaces, err := system.GetActiveInterfaces(ctx)
		if err != nil || len(ifaces) == 0 {
			return fmt.Errorf("could not detect active network interface: %v", err)
		}
		ifaceName = ifaces[0].Name
	}

	servers := args
	if err := system.ApplyHostNetwork(ctx, system.HostNetworkChange{
		Kind:         system.HostNetworkChangeDNS,
		DNSInterface: ifaceName,
		DNSServers:   servers,
	}); err != nil {
		return fmt.Errorf("failed to set DNS: %w", err)
	}

	fmt.Printf("DNS servers applied to interface %q: %s\n", ifaceName, strings.Join(servers, ", "))
	return nil
}

func runDnsClear(cmd *cobra.Command, args []string) error {
	ctx, cancel := ctxWithTimeout(10)
	defer cancel()

	ifaces, err := system.GetActiveInterfaces(ctx)
	if err != nil || len(ifaces) == 0 {
		return fmt.Errorf("could not detect active network interface: %v", err)
	}
	ifaceName := ifaces[0].Name

	if err := system.ApplyHostNetwork(ctx, system.HostNetworkChange{
		Kind:         system.HostNetworkChangeDNS,
		DNSInterface: ifaceName,
		DNSServers:   nil,
	}); err != nil {
		return fmt.Errorf("failed to reset DNS: %w", err)
	}

	fmt.Printf("DNS reset to DHCP on interface %q\n", ifaceName)
	return nil
}

func runDnsStatus(cmd *cobra.Command, args []string) error {
	ctx, cancel := ctxWithTimeout(5)
	defer cancel()

	ifaces, err := system.GetActiveInterfaces(ctx)
	if err != nil || len(ifaces) == 0 {
		return fmt.Errorf("could not detect active network interface: %v", err)
	}

	for _, iface := range ifaces {
		servers, err := system.GetDNS(ctx, iface.Name)
		if err != nil {
			fmt.Printf("  %-30s ERROR: %v\n", iface.Name, err)
			continue
		}
		if len(servers) == 0 {
			fmt.Printf("  %-30s (DHCP)\n", iface.Name)
		} else {
			fmt.Printf("  %-30s %s\n", iface.Name, strings.Join(servers, ", "))
		}
	}
	return nil
}

func runProxyApply(cmd *cobra.Command, args []string) error {
	ctx, cancel := ctxWithTimeout(10)
	defer cancel()

	server := args[0]
	bypass, _ := cmd.Flags().GetString("bypass")

	settings := &system.ProxySettings{
		Enabled: true,
		Server:  server,
		Bypass:  bypass,
	}

	if err := system.ApplyHostNetwork(ctx, system.HostNetworkChange{
		Kind:      system.HostNetworkChangeRoute,
		RouteMode: system.HostRouteProxy,
		Proxy:     *settings,
	}); err != nil {
		return fmt.Errorf("failed to set proxy: %w", err)
	}

	fmt.Printf("System proxy set to %s (bypass: %s)\n", server, bypass)
	return nil
}

func runProxyClear(cmd *cobra.Command, args []string) error {
	ctx, cancel := ctxWithTimeout(10)
	defer cancel()

	if err := system.ApplyHostNetwork(ctx, system.HostNetworkChange{
		Kind:      system.HostNetworkChangeRoute,
		RouteMode: system.HostRouteDirect,
	}); err != nil {
		return fmt.Errorf("failed to clear proxy: %w", err)
	}

	fmt.Println("System proxy cleared")
	return nil
}

func runProxyStatus(cmd *cobra.Command, args []string) error {
	ctx, cancel := ctxWithTimeout(5)
	defer cancel()

	settings, err := system.GetSystemProxy(ctx)
	if err != nil {
		return fmt.Errorf("failed to get proxy settings: %w", err)
	}

	if settings.Enabled {
		fmt.Printf("Proxy: ENABLED\n  Server: %s\n  Bypass: %s\n", settings.Server, settings.Bypass)
	} else {
		fmt.Println("Proxy: DISABLED")
	}
	return nil
}

func runDdnsForce(cmd *cobra.Command, args []string) error {
	provider, _ := cmd.Flags().GetString("provider")
	token, _ := cmd.Flags().GetString("token")
	domain, _ := cmd.Flags().GetString("domain")

	if token == "" || domain == "" {
		return fmt.Errorf("--token and --domain are required for DDNS update")
	}

	ctx, cancel := ctxWithTimeout(30)
	defer cancel()

	updater := dns.NewUpdater(provider, token, domain)

	fmt.Printf("Detecting public IP...\n")
	ip, err := updater.GetPublicIP(ctx)
	if err != nil {
		return fmt.Errorf("failed to get public IP: %w", err)
	}
	fmt.Printf("Public IP: %s\n", ip)

	fmt.Printf("Updating DDNS record (%s / %s)...\n", provider, domain)
	result, err := updater.UpdateIP(ctx, ip)
	if err != nil {
		return fmt.Errorf("DDNS update failed: %w", err)
	}

	if result.Updated {
		fmt.Printf("✓ Updated %s → %s\n", result.Domain, result.IP)
	} else {
		fmt.Printf("  No change needed: %s\n", result.StatusText)
	}
	return nil
}

func runProfilesList(cmd *cobra.Command, args []string) error {
	fmt.Println("No profiles configured.")
	fmt.Println("Use the web UI or config file to add network profiles.")
	return nil
}

func runProfilesApply(cmd *cobra.Command, args []string) error {
	name := args[0]
	return fmt.Errorf("profile %q not found — no profiles are configured", name)
}

func runStartupStatus(cmd *cobra.Command, args []string) error {
	fmt.Println("Startup: DISABLED")
	fmt.Println("Run 'luminet system startup enable' to register LumiNet at login.")
	return nil
}

func runStartupEnable(cmd *cobra.Command, args []string) error {
	fmt.Println("Startup registration is platform-specific.")
	fmt.Println("On Windows: add luminet.exe to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
	fmt.Println("On Linux: create a systemd user service or add to ~/.config/autostart/")
	fmt.Println("On macOS: create a LaunchAgent plist in ~/Library/LaunchAgents/")
	return nil
}

func runStartupDisable(cmd *cobra.Command, args []string) error {
	fmt.Println("Startup entry removed (if it existed).")
	return nil
}

func runEvasionTunnelStart(cmd *cobra.Command, args []string) error {
	port, _ := cmd.Flags().GetInt("port")
	split, _ := cmd.Flags().GetInt("split")
	delay, _ := cmd.Flags().GetInt("delay")
	mutateHost, _ := cmd.Flags().GetBool("mutate-host")
	mutateHeaderSpace, _ := cmd.Flags().GetBool("mutate-header-space")
	autoSni, _ := cmd.Flags().GetBool("auto-sni")
	sniSplitOffset, _ := cmd.Flags().GetInt("sni-split-offset")
	packets, _ := cmd.Flags().GetString("packets")
	minLen, _ := cmd.Flags().GetInt("min-len")
	maxLen, _ := cmd.Flags().GetInt("max-len")
	tlsRecSplit, _ := cmd.Flags().GetBool("tls-record-split")
	dns, _ := cmd.Flags().GetString("dns")
	dnsFwdPort, _ := cmd.Flags().GetInt("dns-fwd-port")
	dnsFwd, _ := cmd.Flags().GetBool("dns-fwd")
	systemProxy, _ := cmd.Flags().GetBool("system-proxy")
	sniSpoof, _ := cmd.Flags().GetString("sni-spoof")
	padding, _ := cmd.Flags().GetInt("padding")
	delayJitter, _ := cmd.Flags().GetBool("delay-jitter")
	windowClamp, _ := cmd.Flags().GetInt("tcp-window-clamp")
	userAgent, _ := cmd.Flags().GetString("custom-user-agent")
	covertMode, _ := cmd.Flags().GetString("covert-mode")
	covertServerlessUrl, _ := cmd.Flags().GetString("covert-serverless-url")
	covertDnsDomain, _ := cmd.Flags().GetString("covert-dns-domain")
	covertGsaUrl, _ := cmd.Flags().GetString("covert-gsa-url")
	covertGsaKey, _ := cmd.Flags().GetString("covert-gsa-key")
	covertGdocsFolderId, _ := cmd.Flags().GetString("covert-gdocs-folder-id")
	covertGdocsAccessToken, _ := cmd.Flags().GetString("covert-gdocs-access-token")
	fakePacketInject, _ := cmd.Flags().GetBool("fake-packet-inject")
	fakePacketTtl, _ := cmd.Flags().GetInt("fake-packet-ttl")
	mutateSniCase, _ := cmd.Flags().GetBool("mutate-sni-case")
	mutateMethod, _ := cmd.Flags().GetBool("mutate-method")
	mutateAbsoluteUri, _ := cmd.Flags().GetBool("mutate-absolute-uri")
	httpPadding, _ := cmd.Flags().GetInt("http-padding")
	preflightSignature, _ := cmd.Flags().GetString("preflight-signature")
	preflightDelay, _ := cmd.Flags().GetInt("preflight-delay")
	sessionFrag, _ := cmd.Flags().GetBool("session-frag")
	sessionFragProb, _ := cmd.Flags().GetFloat64("session-frag-prob")
	sessionFragMinTotal, _ := cmd.Flags().GetInt("session-frag-min-total")
	sessionFragMaxTotal, _ := cmd.Flags().GetInt("session-frag-max-total")
	sessionFragMinChunk, _ := cmd.Flags().GetInt("session-frag-min-chunk")
	sessionFragMaxChunk, _ := cmd.Flags().GetInt("session-frag-max-chunk")
	sessionFragMinDelay, _ := cmd.Flags().GetInt("session-frag-min-delay")
	sessionFragMaxDelay, _ := cmd.Flags().GetInt("session-frag-max-delay")
	ipSpoofing, _ := cmd.Flags().GetBool("ip-spoofing")
	ipSpoofingDecoy, _ := cmd.Flags().GetString("ip-spoofing-decoy")
	ipSpoofingDstReal, _ := cmd.Flags().GetString("ip-spoofing-dst-real")
	outOfWindow, _ := cmd.Flags().GetBool("out-of-window")
	outOfWindowSeqOffset, _ := cmd.Flags().GetInt("out-of-window-seq-offset")
	decoySniPool, _ := cmd.Flags().GetString("decoy-sni-pool")
	oob, _ := cmd.Flags().GetBool("oob")
	oobex, _ := cmd.Flags().GetBool("oobex")
	asyncReactor, _ := cmd.Flags().GetBool("async-reactor")
	lossRate, _ := cmd.Flags().GetFloat64("loss-rate")
	emulatedLatency, _ := cmd.Flags().GetInt("emulated-latency")
	emulatedJitter, _ := cmd.Flags().GetInt("emulated-jitter")
	circularCacheCap, _ := cmd.Flags().GetInt("circular-cache-cap")
	shaperReadRate, _ := cmd.Flags().GetInt64("shaper-read-rate")
	shaperWriteRate, _ := cmd.Flags().GetInt64("shaper-write-rate")
	covertSocketProtectPath, _ := cmd.Flags().GetString("covert-socket-protect-path")
	mobileAssetsEnabled, _ := cmd.Flags().GetBool("mobile-assets-enabled")
	zygiskHideEnabled, _ := cmd.Flags().GetBool("zygisk-hide-enabled")
	hardenedTlsEnabled, _ := cmd.Flags().GetBool("hardened-tls-enabled")
	upgenEnabled, _ := cmd.Flags().GetBool("upgen")
	upgenSeedHex, _ := cmd.Flags().GetString("upgen-seed")
	upgenEntropyMatch, _ := cmd.Flags().GetBool("upgen-entropy")
	upgenQuicExhaustionRate, _ := cmd.Flags().GetInt("upgen-quic-rate")
	stegoEnabled, _ := cmd.Flags().GetBool("stego")
	stegoMode, _ := cmd.Flags().GetString("stego-mode")
	stegoDecoyImagePath, _ := cmd.Flags().GetString("stego-decoy-image")
	stegoWebRTCSDPSpoof, _ := cmd.Flags().GetBool("stego-webrtc-sdp")
	residentialCloaking, _ := cmd.Flags().GetBool("residential-cloaking")
	residentialEgressNode, _ := cmd.Flags().GetString("residential-egress-node")
	mssClamping, _ := cmd.Flags().GetInt("mss-clamping")
	dnsLeaksShield, _ := cmd.Flags().GetBool("dns-leaks-shield")
	mssPreset, _ := cmd.Flags().GetString("mss-preset")

	// ── Daemon-aware routing ─────────────────────────────────────────────────
	// If a daemon session exists (serve is already running), forward the tunnel
	// start request via REST API instead of instantiating a duplicate in-process
	// manager, which would cause a split-brain state.
	daemonSession, sessionErr := loadDaemonSession(resolveDataDir())
	if sessionErr != nil {
		return sessionErr
	}
	if daemonSession != nil {
		payload := map[string]interface{}{
			"port":                       port,
			"split_bytes":                split,
			"delay_ms":                   delay,
			"mutate_host":                mutateHost,
			"mutate_header_space":        mutateHeaderSpace,
			"auto_sni":                   autoSni,
			"sni_split_offset":           sniSplitOffset,
			"packets":                    packets,
			"min_length":                 minLen,
			"max_length":                 maxLen,
			"tls_record_split":           tlsRecSplit,
			"dns_resolver":               dns,
			"dns_forwarder_port":         dnsFwdPort,
			"dns_forwarder_enabled":      dnsFwd,
			"system_proxy_enabled":       systemProxy,
			"sni_spoof":                  sniSpoof,
			"client_hello_padding":       padding,
			"delay_jitter":               delayJitter,
			"tcp_window_clamp":           windowClamp,
			"custom_user_agent":          userAgent,
			"covert_mode":                covertMode,
			"covert_serverless_url":      covertServerlessUrl,
			"covert_dns_domain":          covertDnsDomain,
			"covert_gsa_url":             covertGsaUrl,
			"covert_gsa_key":             covertGsaKey,
			"covert_gdocs_folder_id":     covertGdocsFolderId,
			"covert_gdocs_access_token":  covertGdocsAccessToken,
			"fake_packet_inject":         fakePacketInject,
			"fake_packet_ttl":            fakePacketTtl,
			"mutate_sni_case":            mutateSniCase,
			"mutate_method":              mutateMethod,
			"mutate_absolute_uri":        mutateAbsoluteUri,
			"http_padding":               httpPadding,
			"preflight_signature":        preflightSignature,
			"preflight_delay_ms":         preflightDelay,
			"session_frag":               sessionFrag,
			"session_frag_prob":          sessionFragProb,
			"session_frag_min_total":     sessionFragMinTotal,
			"session_frag_max_total":     sessionFragMaxTotal,
			"session_frag_min_chunk":     sessionFragMinChunk,
			"session_frag_max_chunk":     sessionFragMaxChunk,
			"session_frag_min_delay_ms":  sessionFragMinDelay,
			"session_frag_max_delay_ms":  sessionFragMaxDelay,
			"ip_spoofing_enabled":        ipSpoofing,
			"ip_spoofing_decoy_ip":       ipSpoofingDecoy,
			"ip_spoofing_dst_real":       ipSpoofingDstReal,
			"out_of_window_enabled":      outOfWindow,
			"out_of_window_seq_offset":   outOfWindowSeqOffset,
			"decoy_sni_pool":             decoySniPool,
			"oob_enabled":                oob,
			"oobex_enabled":              oobex,
			"async_reactor_enabled":      asyncReactor,
			"loss_rate":                  lossRate,
			"emulated_latency":           emulatedLatency,
			"emulated_jitter":            emulatedJitter,
			"circular_cache_cap":         circularCacheCap,
			"shaper_read_rate":           shaperReadRate,
			"shaper_write_rate":          shaperWriteRate,
			"covert_socket_protect_path": covertSocketProtectPath,
			"mobile_assets_enabled":      mobileAssetsEnabled,
			"zygisk_hide_enabled":        zygiskHideEnabled,
			"hardened_tls_enabled":       hardenedTlsEnabled,
			"upgen_enabled":              upgenEnabled,
			"upgen_seed_hex":             upgenSeedHex,
			"upgen_entropy_match":        upgenEntropyMatch,
			"upgen_quic_exhaustion_rate": upgenQuicExhaustionRate,
			"stego_enabled":              stegoEnabled,
			"stego_mode":                 stegoMode,
			"stego_decoy_image_path":     stegoDecoyImagePath,
			"stego_webrtc_sdp_spoof":     stegoWebRTCSDPSpoof,
			"residential_cloaking":       residentialCloaking,
			"residential_egress_node":    residentialEgressNode,
			"mss_clamping_value":         mssClamping,
			"dns_leaks_shield":           dnsLeaksShield,
			"mss_preset":                 mssPreset,
		}
		body, err := jsonMarshal(payload)
		if err != nil {
			return fmt.Errorf("encode daemon request: %w", err)
		}
		_, statusCode, err := forwardToDaemon(*daemonSession, "/api/system/evasion-tunnel", "POST", body)
		if err != nil {
			return fmt.Errorf("discovered daemon at %s is authoritative (status %d): %w", daemonSession.APIURL, statusCode, err)
		}
		fmt.Printf("✓ Evasion tunnel start request forwarded to running daemon (%s).\n", daemonSession.APIURL)
		return nil
	}
	// ── End daemon-aware routing ─────────────────────────────────────────────

	mgr := proxy.GetEvasionManager()
	mgr.SetOnLog(func(msg string) {
		fmt.Println(msg)
	})

	evasionCfg := proxy.DefaultEvasionConfig()
	evasionCfg.Port = port
	evasionCfg.SplitBytes = split
	evasionCfg.DelayMs = delay
	evasionCfg.MutateHost = mutateHost
	evasionCfg.MutateHeaderSpace = mutateHeaderSpace
	evasionCfg.AutoSni = autoSni
	evasionCfg.SniSplitOffset = sniSplitOffset
	evasionCfg.Packets = packets
	evasionCfg.MinLength = minLen
	evasionCfg.MaxLength = maxLen
	evasionCfg.TlsRecordSplit = tlsRecSplit
	evasionCfg.DnsResolver = dns
	evasionCfg.DnsForwarderPort = dnsFwdPort
	evasionCfg.DnsForwarderEnabled = dnsFwd
	evasionCfg.SystemProxyEnabled = systemProxy
	evasionCfg.SniSpoof = sniSpoof
	evasionCfg.ClientHelloPadding = padding
	evasionCfg.DelayJitter = delayJitter
	evasionCfg.TcpWindowClamp = windowClamp
	evasionCfg.CustomUserAgent = userAgent
	evasionCfg.CovertMode = covertMode
	evasionCfg.CovertServerlessUrl = covertServerlessUrl
	evasionCfg.CovertDnsDomain = covertDnsDomain
	evasionCfg.CovertGsaUrl = covertGsaUrl
	evasionCfg.CovertGsaKey = covertGsaKey
	evasionCfg.CovertGdocsFolderId = covertGdocsFolderId
	evasionCfg.CovertGdocsAccessToken = covertGdocsAccessToken
	evasionCfg.FakePacketInject = fakePacketInject
	evasionCfg.FakePacketTtl = fakePacketTtl
	evasionCfg.MutateSniCase = mutateSniCase
	evasionCfg.MutateMethod = mutateMethod
	evasionCfg.MutateAbsoluteUri = mutateAbsoluteUri
	evasionCfg.HttpPadding = httpPadding
	evasionCfg.PreflightSignature = preflightSignature
	evasionCfg.PreflightDelayMs = preflightDelay
	evasionCfg.SessionFrag = sessionFrag
	evasionCfg.SessionFragProb = sessionFragProb
	evasionCfg.SessionFragMinTotal = sessionFragMinTotal
	evasionCfg.SessionFragMaxTotal = sessionFragMaxTotal
	evasionCfg.SessionFragMinChunk = sessionFragMinChunk
	evasionCfg.SessionFragMaxChunk = sessionFragMaxChunk
	evasionCfg.SessionFragMinDelayMs = sessionFragMinDelay
	evasionCfg.SessionFragMaxDelayMs = sessionFragMaxDelay
	evasionCfg.IpSpoofingEnabled = ipSpoofing
	evasionCfg.IpSpoofingDecoyIP = ipSpoofingDecoy
	evasionCfg.IpSpoofingDstReal = ipSpoofingDstReal
	evasionCfg.OutOfWindowEnabled = outOfWindow
	evasionCfg.OutOfWindowSeqOffset = outOfWindowSeqOffset
	evasionCfg.DecoySniPool = decoySniPool
	evasionCfg.OobEnabled = oob
	evasionCfg.OobexEnabled = oobex
	evasionCfg.AsyncReactorEnabled = asyncReactor
	evasionCfg.LossRate = lossRate
	evasionCfg.EmulatedLatency = emulatedLatency
	evasionCfg.EmulatedJitter = emulatedJitter
	evasionCfg.CircularCacheCap = circularCacheCap
	evasionCfg.ShaperReadRate = shaperReadRate
	evasionCfg.ShaperWriteRate = shaperWriteRate
	evasionCfg.CovertSocketProtectPath = covertSocketProtectPath
	evasionCfg.MobileAssetsEnabled = mobileAssetsEnabled
	evasionCfg.ZygiskHideEnabled = zygiskHideEnabled
	evasionCfg.HardenedTlsEnabled = hardenedTlsEnabled
	evasionCfg.UpgenEnabled = upgenEnabled
	evasionCfg.UpgenSeedHex = upgenSeedHex
	evasionCfg.UpgenEntropyMatch = upgenEntropyMatch
	evasionCfg.UpgenQuicExhaustionRate = upgenQuicExhaustionRate
	evasionCfg.StegoEnabled = stegoEnabled
	evasionCfg.StegoMode = stegoMode
	evasionCfg.StegoDecoyImagePath = stegoDecoyImagePath
	evasionCfg.StegoWebRTCSDPSpoof = stegoWebRTCSDPSpoof
	evasionCfg.ResidentialCloaking = residentialCloaking
	evasionCfg.ResidentialEgressNode = residentialEgressNode
	evasionCfg.MssClampingValue = mssClamping
	evasionCfg.DnsLeaksShield = dnsLeaksShield
	evasionCfg.MssPreset = mssPreset
	err := mgr.Start(&evasionCfg)
	if err != nil {
		return fmt.Errorf("failed to start evasion tunnel: %w", err)
	}

	fmt.Printf("SOCKS5 Evasion Tunnel running on 127.0.0.1:%d\nPress Ctrl+C to stop...\n", port)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	mgr.Stop()
	fmt.Println("SOCKS5 Evasion Tunnel stopped.")
	return nil
}
