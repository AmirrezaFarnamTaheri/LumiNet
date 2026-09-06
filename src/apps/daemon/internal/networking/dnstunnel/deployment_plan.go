package dnstunnel

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

var deploymentDNSLabelRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

type DeploymentPlanRequest struct {
	TunnelSubdomain string `json:"tunnel_subdomain"`
	NameserverHost  string `json:"nameserver_host"`
	ServerIPv4      string `json:"server_ipv4"`
	ServerIPv6      string `json:"server_ipv6,omitempty"`
	MTU             int    `json:"mtu,omitempty"`
	TunnelMode      string `json:"tunnel_mode,omitempty"`
	TargetPort      int    `json:"target_port,omitempty"`
	ListenPort      int    `json:"listen_port,omitempty"`
	ServiceUser     string `json:"service_user,omitempty"`
}

type DNSRecordPlan struct{ Type, Name, Value string }

type DeploymentPlan struct {
	TunnelSubdomain   string          `json:"tunnel_subdomain"`
	NameserverHost    string          `json:"nameserver_host"`
	MTU               int             `json:"mtu"`
	TunnelMode        string          `json:"tunnel_mode"`
	TargetPort        int             `json:"target_port"`
	ListenPort        int             `json:"listen_port"`
	RedirectUDPPort   int             `json:"redirect_udp_port"`
	ServiceUser       string          `json:"service_user"`
	RequiredRecords   []DNSRecordPlan `json:"required_records"`
	Preflight         []string        `json:"preflight"`
	MutationSteps     []string        `json:"mutation_steps"`
	RollbackSteps     []string        `json:"rollback_steps"`
	RequiresRoot      bool            `json:"requires_root"`
	DownloadsBinary   bool            `json:"downloads_binary"`
	MutatesFirewall   bool            `json:"mutates_firewall"`
	WritesSystemd     bool            `json:"writes_systemd"`
	GeneratesKeys     bool            `json:"generates_keys"`
	PerformsNetworkIO bool            `json:"performs_network_io"`
	Invariants        []string        `json:"invariants"`
}

func BuildDeploymentPlan(req DeploymentPlanRequest) (DeploymentPlan, error) {
	tunnel := strings.Trim(strings.TrimSpace(req.TunnelSubdomain), ".")
	ns := strings.Trim(strings.TrimSpace(req.NameserverHost), ".")
	if err := validateDeploymentDNSName(tunnel); err != nil {
		return DeploymentPlan{}, fmt.Errorf("tunnel_subdomain: %w", err)
	}
	if err := validateDeploymentDNSName(ns); err != nil {
		return DeploymentPlan{}, fmt.Errorf("nameserver_host: %w", err)
	}
	if tunnel == ns || strings.HasSuffix(ns, "."+tunnel) {
		return DeploymentPlan{}, fmt.Errorf("nameserver_host must not be inside the delegated tunnel subdomain")
	}
	ipv4 := net.ParseIP(strings.TrimSpace(req.ServerIPv4))
	if ipv4 == nil || ipv4.To4() == nil || !ipv4.IsGlobalUnicast() || ipv4.IsPrivate() {
		return DeploymentPlan{}, fmt.Errorf("server_ipv4 must be a public global-unicast IPv4 address")
	}
	ipv6Text := strings.TrimSpace(req.ServerIPv6)
	var ipv6 net.IP
	if ipv6Text != "" {
		ipv6 = net.ParseIP(ipv6Text)
		if ipv6 == nil || ipv6.To4() != nil || !ipv6.IsGlobalUnicast() || ipv6.IsPrivate() {
			return DeploymentPlan{}, fmt.Errorf("server_ipv6 must be a public global-unicast IPv6 address")
		}
	}
	mtu := req.MTU
	if mtu == 0 {
		mtu = 1232
	}
	if mtu < 512 || mtu > 1400 {
		return DeploymentPlan{}, fmt.Errorf("mtu must be 512..1400")
	}
	mode := strings.ToLower(strings.TrimSpace(req.TunnelMode))
	if mode == "" {
		mode = "socks"
	}
	if mode != "socks" && mode != "ssh" {
		return DeploymentPlan{}, fmt.Errorf("tunnel_mode must be socks or ssh")
	}
	target := req.TargetPort
	if target == 0 {
		if mode == "socks" {
			target = 1080
		} else {
			target = 22
		}
	}
	if target < 1 || target > 65535 {
		return DeploymentPlan{}, fmt.Errorf("target_port must be 1..65535")
	}
	listen := req.ListenPort
	if listen == 0 {
		listen = 5300
	}
	if listen < 1024 || listen > 65535 {
		return DeploymentPlan{}, fmt.Errorf("listen_port must be 1024..65535 so privileged UDP/53 remains a separate redirect boundary")
	}
	user := strings.TrimSpace(req.ServiceUser)
	if user == "" {
		user = "dnstt"
	}
	if len(user) > 32 || !regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`).MatchString(user) {
		return DeploymentPlan{}, fmt.Errorf("service_user is invalid")
	}
	plan := DeploymentPlan{TunnelSubdomain: tunnel, NameserverHost: ns, MTU: mtu, TunnelMode: mode, TargetPort: target, ListenPort: listen, RedirectUDPPort: 53, ServiceUser: user, RequiresRoot: true, DownloadsBinary: false, MutatesFirewall: false, WritesSystemd: false, GeneratesKeys: false, PerformsNetworkIO: false,
		RequiredRecords: []DNSRecordPlan{{Type: "A", Name: ns, Value: ipv4.String()}, {Type: "NS", Name: tunnel, Value: ns}},
		Preflight:       []string{"confirm delegated NS record resolves to the intended nameserver host", "confirm nameserver A/AAAA glue reaches the intended public server", "confirm UDP/53 can reach the host and can be redirected to the unprivileged DNSTT listener", "confirm the selected local forward target is already available before enabling the DNSTT service"},
		MutationSteps:   []string{fmt.Sprintf("create/reuse a non-login service account %s", user), "install a verified DNSTT server binary through the release/install owner", "generate or reuse per-domain server keys with private-key permissions", "write a systemd unit that runs DNSTT as the service user", fmt.Sprintf("redirect inbound UDP/53 to UDP/%d while preserving explicit firewall ownership", listen), "enable and start only after DNS and local-target preflight succeeds"},
		RollbackSteps:   []string{"stop and disable the DNSTT service", "remove only the task-owned UDP/53 redirect/firewall rules", "restore the previous service unit/config revision if one existed", "retain keys unless the operator explicitly requests key destruction"},
		Invariants:      []string{"the planner performs no package download, SSH command, key generation, firewall mutation, systemd write, or service restart", "DNS delegation records are modeled separately from host firewall/service state", "private key material is never returned by the planner", "port 53 privilege is isolated from the unprivileged DNSTT listener via an explicit redirect boundary", "reconfiguration requires an explicit rollback path and must not delete existing keys by default"},
	}
	if ipv6 != nil {
		plan.RequiredRecords = append(plan.RequiredRecords, DNSRecordPlan{Type: "AAAA", Name: ns, Value: ipv6.String()})
	}
	return plan, nil
}

func validateDeploymentDNSName(name string) error {
	if name == "" || len(name) > 253 {
		return fmt.Errorf("must be a bounded DNS name")
	}
	for _, l := range strings.Split(name, ".") {
		if len(l) > 63 || !deploymentDNSLabelRE.MatchString(l) {
			return fmt.Errorf("invalid DNS label %q", l)
		}
	}
	return nil
}
