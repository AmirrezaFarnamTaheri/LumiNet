// Package firewall provides per-app and per-domain firewall rules.
// Ported from Rethink App's FirewallManager and FirewallRuleset.
//
// Features:
// - Per-app internet blocking (foreground/background/metered/unmetered)
// - Per-domain block/trust rules
// - Per-IP block/trust rules
// - Isolate mode (block all except trusted)
// - Temporary allow with expiry
// - Universal lockdown
// - New app blocking
package firewall

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FirewallStatus represents the firewall status for an app.
type Status int

const (
	StatusNone           Status = 0
	StatusBypassUniversal Status = 1
	StatusExclude         Status = 2
	StatusIsolate         Status = 3
	StatusBypassDNS       Status = 4
)

// ConnectionStatus represents allowed connection types.
type ConnectionStatus int

const (
	ConnBothBlocked    ConnectionStatus = 0
	ConnUnmeteredOnly  ConnectionStatus = 1 // WiFi only
	ConnMeteredOnly    ConnectionStatus = 2 // Mobile only
	ConnAllow          ConnectionStatus = 3
)

// RuleType represents the type of firewall rule.
type RuleType string

const (
	RuleNone              RuleType = "RULE0"
	RuleBlockApp          RuleType = "RULE1"
	RuleBlockNewInstall   RuleType = "RULE2"
	RuleBlockMetered      RuleType = "RULE3"
	RuleBlockUnmetered    RuleType = "RULE4"
	RuleIsolate           RuleType = "RULE5"
	RuleBypassDNSFirewall RuleType = "RULE6"
	RuleBlockIP           RuleType = "RULE7"
	RuleTrustIP           RuleType = "RULE8"
	RuleBlockDomain       RuleType = "RULE9"
	RuleTrustDomain       RuleType = "RULE10"
	RuleDNSBlocked        RuleType = "RULE11"
	RuleDeviceLock        RuleType = "RULE12"
	RuleBlockBackground   RuleType = "RULE13"
	RuleUnknownApp        RuleType = "RULE14"
	RuleBlockUDP          RuleType = "RULE15"
	RuleBlockNTP          RuleType = "RULE16"
	RuleDNSBypass         RuleType = "RULE17"
	RuleHTTPBlock         RuleType = "RULE18"
	RuleUniversalLockdown RuleType = "RULE19"
	RuleTempAllow         RuleType = "RULE20"
)

// AppFirewallRule represents a per-app firewall configuration.
type AppFirewallRule struct {
	UID             int              `json:"uid"`
	PackageName     string           `json:"packageName"`
	Status          Status           `json:"status"`
	ConnectionStatus ConnectionStatus `json:"connectionStatus"`
	IsSystemApp     bool             `json:"isSystemApp"`
	IsForeground    bool             `json:"isForeground"`
	InstalledAt     time.Time        `json:"installedAt"`
}

// DomainRule represents a per-domain firewall rule.
type DomainRule struct {
	Domain  string `json:"domain"`
	UID     int    `json:"uid"` // -1 for global rules
	Blocked bool   `json:"blocked"`
	Trusted bool   `json:"trusted"`
}

// IPRule represents a per-IP firewall rule.
type IPRule struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"` // 0 = all ports
	UID     int    `json:"uid"` // -1 for global rules
	Blocked bool   `json:"blocked"`
	Trusted bool   `json:"trusted"`
}

// IPRuleCIDR wraps a parsed net.IPNet for CIDR-matching.
type IPRuleCIDR struct {
	IPNet  *net.IPNet
	IPRule *IPRule
}

// FirewallManager manages all firewall rules.
type FirewallManager struct {
	mu              sync.RWMutex
	appRules        map[int]*AppFirewallRule     // UID -> rule
	domainRules     map[string]*DomainRule       // domain -> rule
	ipRules         map[string]*IPRule           // ip:port -> rule
	cidrRules       []*IPRuleCIDR                // parsed CIDR subnet rules
	tempAllows      map[int]time.Time            // UID -> expiry time
	universalLock   bool
	blockNewInstalls bool
	blockUDP        bool
	blockNTP        bool
	blockHTTP       bool
}

// NewFirewallManager creates a new firewall manager.
func NewFirewallManager() *FirewallManager {
	return &FirewallManager{
		appRules:    make(map[int]*AppFirewallRule),
		domainRules: make(map[string]*DomainRule),
		ipRules:     make(map[string]*IPRule),
		tempAllows:  make(map[int]time.Time),
	}
}

// ShouldAllow checks if a connection should be allowed.
// Returns (allowed, rule).
func (fm *FirewallManager) ShouldAllow(uid int, domain string, ip string, port int, isMetered bool, isForeground bool) (bool, RuleType) {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	// Universal lockdown
	if fm.universalLock {
		// Check temp allow
		if expiry, ok := fm.tempAllows[uid]; ok && time.Now().Before(expiry) {
			return true, RuleTempAllow
		}
		return false, RuleUniversalLockdown
	}

	// Check app rule
	if rule, ok := fm.appRules[uid]; ok {
		switch rule.Status {
		case StatusExclude:
			return false, RuleBlockApp
		case StatusIsolate:
			// In isolate mode, only allow if domain/IP is trusted
			if fm.isDomainTrusted(domain) || fm.isIPTrusted(ip, port) {
				return true, RuleTrustDomain
			}
			return false, RuleIsolate
		case StatusBypassUniversal:
			return true, RuleBypassDNSFirewall
		}

		// Check connection status
		switch rule.ConnectionStatus {
		case ConnBothBlocked:
			return false, RuleBlockApp
		case ConnUnmeteredOnly:
			if isMetered {
				return false, RuleBlockMetered
			}
		case ConnMeteredOnly:
			if !isMetered {
				return false, RuleBlockUnmetered
			}
		}

		// Block background traffic
		if !isForeground && !rule.IsForeground {
			if rule.Status == StatusNone {
				return false, RuleBlockBackground
			}
		}
	}

	// Block new installs
	if fm.blockNewInstalls {
		if rule, ok := fm.appRules[uid]; ok && time.Since(rule.InstalledAt) < 24*time.Hour {
			return false, RuleBlockNewInstall
		}
	}

	// Check domain rules
	if rule, ok := fm.domainRules[domain]; ok {
		if rule.Blocked {
			if rule.UID == -1 || rule.UID == uid {
				return false, RuleBlockDomain
			}
		}
		if rule.Trusted {
			if rule.UID == -1 || rule.UID == uid {
				return true, RuleTrustDomain
			}
		}
	}

	// Check IP rules (exact match)
	ipKey := ipPortKey(ip, port)
	if rule, ok := fm.ipRules[ipKey]; ok {
		if rule.Blocked {
			if rule.UID == -1 || rule.UID == uid {
				return false, RuleBlockIP
			}
		}
		if rule.Trusted {
			if rule.UID == -1 || rule.UID == uid {
				return true, RuleTrustIP
			}
		}
	}

	// Check IP rules (CIDR subnet match - similar to ipset in antizapret)
	parsedIP := net.ParseIP(ip)
	if parsedIP != nil {
		for _, r := range fm.cidrRules {
			if (r.IPRule.Port == 0 || r.IPRule.Port == port) && r.IPNet.Contains(parsedIP) {
				if r.IPRule.Blocked {
					if r.IPRule.UID == -1 || r.IPRule.UID == uid {
						return false, RuleBlockIP
					}
				}
				if r.IPRule.Trusted {
					if r.IPRule.UID == -1 || r.IPRule.UID == uid {
						return true, RuleTrustIP
					}
				}
			}
		}
	}

	// Check temp allow
	if expiry, ok := fm.tempAllows[uid]; ok && time.Now().Before(expiry) {
		return true, RuleTempAllow
	}

	// Block UDP if configured
	if fm.blockUDP {
		// Would need protocol info
	}

	// Block NTP if configured
	if fm.blockNTP && port == 123 {
		return false, RuleBlockNTP
	}

	return true, RuleNone
}

// SetAppRule sets a firewall rule for an app.
func (fm *FirewallManager) SetAppRule(rule *AppFirewallRule) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	fm.appRules[rule.UID] = rule
}

// SetDomainRule sets a domain firewall rule.
func (fm *FirewallManager) SetDomainRule(rule *DomainRule) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	fm.domainRules[rule.Domain] = rule
}

// SetIPRule sets an IP firewall rule.
func (fm *FirewallManager) SetIPRule(rule *IPRule) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	
	key := ipPortKey(rule.IP, rule.Port)
	fm.ipRules[key] = rule

	// If the IP contains a subnet slash, parse and cache as a CIDR rule
	if strings.Contains(rule.IP, "/") {
		_, ipnet, err := net.ParseCIDR(rule.IP)
		if err == nil {
			found := false
			for i, r := range fm.cidrRules {
				if r.IPRule.IP == rule.IP && r.IPRule.Port == rule.Port && r.IPRule.UID == rule.UID {
					fm.cidrRules[i] = &IPRuleCIDR{IPNet: ipnet, IPRule: rule}
					found = true
					break
				}
			}
			if !found {
				fm.cidrRules = append(fm.cidrRules, &IPRuleCIDR{IPNet: ipnet, IPRule: rule})
			}
		}
	}
}

// SetTempAllow sets a temporary allow for an app (default 15 minutes).
func (fm *FirewallManager) SetTempAllow(uid int, duration time.Duration) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	fm.tempAllows[uid] = time.Now().Add(duration)
}

// SetUniversalLockdown enables/disables universal lockdown mode.
func (fm *FirewallManager) SetUniversalLockdown(enabled bool) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	fm.universalLock = enabled
}

// SetBlockNewInstalls enables/disables blocking of newly installed apps.
func (fm *FirewallManager) SetBlockNewInstalls(enabled bool) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	fm.blockNewInstalls = enabled
}

func (fm *FirewallManager) isDomainTrusted(domain string) bool {
	if rule, ok := fm.domainRules[domain]; ok {
		return rule.Trusted
	}
	return false
}

func (fm *FirewallManager) isIPTrusted(ip string, port int) bool {
	ipKey := ipPortKey(ip, port)
	if rule, ok := fm.ipRules[ipKey]; ok {
		return rule.Trusted
	}
	// Check wildcard IP
	wildcardKey := ipPortKey("*.*.*.*", 0)
	if rule, ok := fm.ipRules[wildcardKey]; ok {
		return rule.Trusted
	}
	return false
}

func ipPortKey(ip string, port int) string {
	if port == 0 {
		return ip
	}
	return ip + ":" + strconv.Itoa(port)
}

// FirewallStats holds firewall statistics.
type FirewallStats struct {
	TotalApps       int `json:"totalApps"`
	BlockedApps     int `json:"blockedApps"`
	TrustedDomains  int `json:"trustedDomains"`
	BlockedDomains  int `json:"blockedDomains"`
	TrustedIPs      int `json:"trustedIPs"`
	BlockedIPs      int `json:"blockedIPs"`
	TempAllows      int `json:"tempAllows"`
	UniversalLock   bool `json:"universalLock"`
}

// Stats returns current firewall statistics.
func (fm *FirewallManager) Stats() FirewallStats {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	stats := FirewallStats{
		TotalApps:     len(fm.appRules),
		TempAllows:    len(fm.tempAllows),
		UniversalLock: fm.universalLock,
	}

	for _, rule := range fm.appRules {
		if rule.Status == StatusExclude {
			stats.BlockedApps++
		}
	}
	for _, rule := range fm.domainRules {
		if rule.Blocked {
			stats.BlockedDomains++
		}
		if rule.Trusted {
			stats.TrustedDomains++
		}
	}
	for _, rule := range fm.ipRules {
		if rule.Blocked {
			stats.BlockedIPs++
		}
		if rule.Trusted {
			stats.TrustedIPs++
		}
	}

	return stats
}
