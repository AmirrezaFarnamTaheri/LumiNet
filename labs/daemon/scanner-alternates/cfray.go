// Package scanner implements network scanning and reconnaissance.
// Ported from: cfray
// Target path: server/internal/scanner/cfray.go

package scanner

import (
	"context"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"
)

// CfrayScanner handles Cloudflare subnet scanning and validation probes.
type CfrayScanner struct {
	cfSubnets []string
	budget    chan struct{}
}

// NewCfrayScanner initializes the cfray scanner with a concurrency throttle
// (_wait_budget) to evade 429 rate-limiting bans.
func NewCfrayScanner(concurrencyLimit int) *CfrayScanner {
	return &CfrayScanner{
		// A few mock CF subnets
		cfSubnets: []string{"104.16.0.0/12", "172.64.0.0/13", "188.114.96.0/20"},
		budget:    make(chan struct{}, concurrencyLimit),
	}
}

// GenerateRandomCfIPs randomly samples IP addresses within the known Cloudflare subnets.
func (s *CfrayScanner) GenerateRandomCfIPs(count int) ([]string, error) {
	var ips []string
	
	for i := 0; i < count; i++ {
		subnet := s.cfSubnets[rand.Intn(len(s.cfSubnets))]
		_, ipnet, err := net.ParseCIDR(subnet)
		if err != nil {
			return nil, err
		}
		
		ip := make(net.IP, len(ipnet.IP))
		copy(ip, ipnet.IP)
		
		// Randomize host portion
		for j := range ip {
			if ipnet.Mask[j] == 0 {
				ip[j] = byte(rand.Intn(256))
			}
		}
		
		ips = append(ips, ip.String())
	}
	
	return ips, nil
}

// waitBudget implements the _wait_budget concurrency throttle.
func (s *CfrayScanner) waitBudget(ctx context.Context) error {
	select {
	case s.budget <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// releaseBudget returns a token to the concurrency budget.
func (s *CfrayScanner) releaseBudget() {
	<-s.budget
}

// ResolveIsCF acts as a validation probe to determine if an IP is effectively
// serving Cloudflare responses.
func (s *CfrayScanner) ResolveIsCF(ctx context.Context, ip string) (bool, error) {
	if err := s.waitBudget(ctx); err != nil {
		return false, err
	}
	defer s.releaseBudget()

	// Simulated validation probe (TCP SYN to 443, expecting CF headers)
	log.Printf("cfray: probing %s to resolve if CF", ip)
	time.Sleep(50 * time.Millisecond) // Simulate RTT
	
	// Random success rate for the porting simulation
	isValid := rand.Float32() > 0.5
	return isValid, nil
}

// ProgressiveSpeedTest runs a funnel of speed tests across multiple IPs, filtering down.
func (s *CfrayScanner) ProgressiveSpeedTest(ctx context.Context, ips []string) []string {
	var validIPs []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			
			ok, err := s.ResolveIsCF(ctx, target)
			if err == nil && ok {
				mu.Lock()
				validIPs = append(validIPs, target)
				mu.Unlock()
			}
		}(ip)
	}
	
	wg.Wait()
	log.Printf("cfray: progressive speed test found %d valid IPs out of %d", len(validIPs), len(ips))
	return validIPs
}
