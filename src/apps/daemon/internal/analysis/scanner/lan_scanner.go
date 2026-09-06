
package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// LanDevice represents a discovered network device.
type LanDevice struct {
	IP       string
	MAC      string
	Hostname string
	LastSeen time.Time
}

// LanScanner monitors active local network devices using ICMP pings and DNS lookups.
type LanScanner struct {
	mu      sync.RWMutex
	devices map[string]*LanDevice // IP -> Device
}

// NewLanScanner creates a new LAN scanner.
func NewLanScanner() *LanScanner {
	return &LanScanner{
		devices: make(map[string]*LanDevice),
	}
}

// ScanSubnet probes IP addresses within the local subnet.
// subnetIP: e.g. "192.168.1.0/24"
func (s *LanScanner) ScanSubnet(ctx context.Context, subnetCIDR string) ([]LanDevice, error) {
	ip, ipnet, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return nil, fmt.Errorf("lan_scanner: invalid subnet: %w", err)
	}

	var targets []string
	// Generate all IPv4 host addresses in the subnet
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		targets = append(targets, ip.String())
	}

	// Filter out subnet network and broadcast address
	if len(targets) > 2 {
		targets = targets[1 : len(targets)-1]
	}

	var results []LanDevice
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	for _, target := range targets {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		sem <- struct{}{}
		wg.Add(1)
		go func(ipAddr string) {
			defer func() {
				<-sem
				wg.Done()
			}()

			// Use TCP dial probe to common port 80/443 as user-space fallback for ARP
			dialer := net.Dialer{Timeout: 500 * time.Millisecond}
			conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:80", ipAddr))
			success := err == nil
			if err == nil {
				conn.Close()
			} else {
				// Try port 443
				conn, err = dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:443", ipAddr))
				success = err == nil
				if err == nil {
					conn.Close()
				}
			}

			if success {
				hostname := ""
				names, err := net.DefaultResolver.LookupAddr(ctx, ipAddr)
				if err == nil && len(names) > 0 {
					hostname = names[0]
				}

				dev := &LanDevice{
					IP:       ipAddr,
					MAC:      "00:00:00:00:00:00", // ARP MAC requires privileged raw sockets
					Hostname: hostname,
					LastSeen: time.Now(),
				}

				s.mu.Lock()
				s.devices[ipAddr] = dev
				results = append(results, *dev)
				s.mu.Unlock()
			}
		}(target)
	}

	wg.Wait()
	return results, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ActiveDevices returns a snapshot of active discovered devices.
func (s *LanScanner) ActiveDevices() []LanDevice {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []LanDevice
	for _, d := range s.devices {
		if time.Since(d.LastSeen) < 10*time.Minute {
			list = append(list, *d)
		}
	}
	return list
}
