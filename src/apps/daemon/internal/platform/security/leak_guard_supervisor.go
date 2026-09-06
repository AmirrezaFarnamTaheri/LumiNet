package security

import (
	"strings"
	"sync"
	"time"
)

// LeakType identifies DNS, IPv6, or WebRTC leak vectors
type LeakType string

const (
	LeakTypeDNS    LeakType = "DNS_LEAK"
	LeakTypeIPv6   LeakType = "IPV6_LEAK"
	LeakTypeWebRTC LeakType = "WEBRTC_STUN_LEAK"
)

// LeakEvent records detected leak anomalies
type LeakEvent struct {
	Type        LeakType
	TargetAddr  string
	AdapterName string
	DetectedAt  time.Time
	Blocked     bool
}

// LeakGuardSupervisor enforces killswitch rules and stops traffic when leaks or VPN drops occur
type LeakGuardSupervisor struct {
	tunnelInterface string
	allowedDNS      []string
	blockIPv6       bool
	killswitchOn    bool
	leakEvents      []LeakEvent
	mu              sync.RWMutex
}

// NewLeakGuardSupervisor creates a new leak guard supervisor
func NewLeakGuardSupervisor(tunnelInterface string, allowedDNS []string, blockIPv6 bool) *LeakGuardSupervisor {
	return &LeakGuardSupervisor{
		tunnelInterface: tunnelInterface,
		allowedDNS:      allowedDNS,
		blockIPv6:       blockIPv6,
		killswitchOn:    true,
	}
}

// ValidateOutboundDestination evaluates if an outbound packet violates leak policies
func (s *LeakGuardSupervisor) ValidateOutboundDestination(dstIP string, dstPort uint16, iface string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If killswitch is on and interface is not the protected tunnel
	if s.killswitchOn && iface != s.tunnelInterface {
		// If DNS port 53 / 853 / 5353 sent outside tunnel
		if dstPort == 53 || dstPort == 853 || dstPort == 5353 {
			allowed := false
			for _, dns := range s.allowedDNS {
				if dstIP == dns {
					allowed = true
					break
				}
			}
			if !allowed {
				s.leakEvents = append(s.leakEvents, LeakEvent{
					Type:        LeakTypeDNS,
					TargetAddr:  dstIP,
					AdapterName: iface,
					DetectedAt:  time.Now(),
					Blocked:     true,
				})
				return false // Block leak
			}
		}

		// If IPv6 enabled but blockIPv6 policy is active
		if s.blockIPv6 && strings.Contains(dstIP, ":") {
			s.leakEvents = append(s.leakEvents, LeakEvent{
				Type:        LeakTypeIPv6,
				TargetAddr:  dstIP,
				AdapterName: iface,
				DetectedAt:  time.Now(),
				Blocked:     true,
			})
			return false // Block IPv6 leak
		}
	}

	return true
}

// SetKillswitch toggles killswitch activation
func (s *LeakGuardSupervisor) SetKillswitch(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.killswitchOn = enabled
}

// TotalLeaksDetected returns total recorded leak events
func (s *LeakGuardSupervisor) TotalLeaksDetected() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.leakEvents)
}
