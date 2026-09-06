package diagnostics

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

type SNIGatewayPlanRequest struct {
	PublicIP               string   `json:"public_ip"`
	RequirePublicIP        bool     `json:"require_public_ip,omitempty"`
	DNSPort                int      `json:"dns_port,omitempty"`
	TLSRouterPort          int      `json:"tls_router_port,omitempty"`
	HTTPRedirectPort       int      `json:"http_redirect_port,omitempty"`
	CompetingDNSServices   []string `json:"competing_dns_services,omitempty"`
	DNSConfigured          bool     `json:"dns_configured,omitempty"`
	TLSRouterConfigured    bool     `json:"tls_router_configured,omitempty"`
	HTTPRedirectConfigured bool     `json:"http_redirect_configured,omitempty"`
	ListenerEndpoint       string   `json:"listener_endpoint,omitempty"`
	UpstreamEndpoint       string   `json:"upstream_endpoint,omitempty"`
}

type SNIGatewayPlan struct {
	Ready         bool     `json:"ready"`
	Conflicts     []string `json:"conflicts"`
	ApplyOrder    []string `json:"apply_order"`
	RollbackOrder []string `json:"rollback_order"`
	ReadOnly      bool     `json:"read_only"`
	SelfLoop      bool     `json:"self_loop"`
}

func isPrivateIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

func parseLiteralEndpoint(raw string) (net.IP, int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, 0, nil
	}
	host, portRaw, err := net.SplitHostPort(raw)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid endpoint %q: %w", raw, err)
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return nil, 0, fmt.Errorf("endpoint %q must use a literal IP to keep planning offline", raw)
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil || port < 1 || port > 65535 {
		return nil, 0, fmt.Errorf("endpoint %q has invalid port", raw)
	}
	return ip, port, nil
}

func sniEndpointSelfLoop(listenerIP net.IP, listenerPort int, upstreamIP net.IP, upstreamPort int) bool {
	if listenerIP == nil || upstreamIP == nil {
		return false
	}
	if listenerPort != upstreamPort {
		return false
	}
	if listenerIP.Equal(upstreamIP) {
		return true
	}
	return upstreamIP.IsLoopback() && (listenerIP.IsLoopback() || listenerIP.IsUnspecified())
}

func BuildSNIGatewayPlan(req SNIGatewayPlanRequest) (SNIGatewayPlan, error) {
	plan := SNIGatewayPlan{ReadOnly: true, Conflicts: []string{}}
	ip := net.ParseIP(strings.TrimSpace(req.PublicIP))
	if req.RequirePublicIP {
		if ip == nil || isPrivateIP(ip) {
			plan.Conflicts = append(plan.Conflicts, "public routable IP required")
		}
	} else if strings.TrimSpace(req.PublicIP) != "" && ip == nil {
		return SNIGatewayPlan{}, fmt.Errorf("invalid gateway IP")
	}
	ports := []struct {
		name  string
		value int
	}{{"dns", req.DNSPort}, {"tls-router", req.TLSRouterPort}, {"http-redirect", req.HTTPRedirectPort}}
	seen := map[int]string{}
	for _, p := range ports {
		if p.value == 0 {
			continue
		}
		if p.value < 1 || p.value > 65535 {
			return SNIGatewayPlan{}, fmt.Errorf("%s port out of range", p.name)
		}
		if previous, ok := seen[p.value]; ok {
			plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("port %d shared by %s and %s", p.value, previous, p.name))
		}
		seen[p.value] = p.name
	}
	services := make([]string, 0, len(req.CompetingDNSServices))
	for _, raw := range req.CompetingDNSServices {
		v := strings.TrimSpace(raw)
		if v == "" || len(v) > 128 {
			return SNIGatewayPlan{}, fmt.Errorf("invalid competing DNS service")
		}
		services = append(services, v)
	}
	sort.Strings(services)
	for _, service := range services {
		plan.Conflicts = append(plan.Conflicts, "DNS listener conflict: "+service)
	}
	listenerIP, listenerPort, err := parseLiteralEndpoint(req.ListenerEndpoint)
	if err != nil {
		return SNIGatewayPlan{}, err
	}
	upstreamIP, upstreamPort, err := parseLiteralEndpoint(req.UpstreamEndpoint)
	if err != nil {
		return SNIGatewayPlan{}, err
	}
	if (listenerIP == nil) != (upstreamIP == nil) {
		return SNIGatewayPlan{}, fmt.Errorf("listener_endpoint and upstream_endpoint must be supplied together")
	}
	if sniEndpointSelfLoop(listenerIP, listenerPort, upstreamIP, upstreamPort) {
		plan.SelfLoop = true
		plan.Conflicts = append(plan.Conflicts, "SNI upstream would loop back into the local listener")
	}
	plan.ApplyOrder = []string{"validate configuration", "validate DNS ownership", "start TLS router", "publish DNS steering", "enable HTTP redirect if requested", "observe health"}
	plan.RollbackOrder = []string{"disable HTTP redirect", "remove DNS steering", "stop TLS router", "restore prior DNS ownership", "verify original listeners"}
	plan.Ready = len(plan.Conflicts) == 0 && req.DNSConfigured && req.TLSRouterConfigured && (!req.HTTPRedirectConfigured || req.HTTPRedirectPort != 0)
	return plan, nil
}
