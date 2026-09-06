package scanner

import (
	"context"
	"crypto/rand"
	"math/big"
	"net"
	"sync"
	"time"
)

// IPDiscoveryScanner performs parallel TCP dial tests on random IP ranges.
type IPDiscoveryScanner struct {
	cidrBlocks []string
	timeout    time.Duration
	results    chan string
	mu         sync.Mutex
	stop       chan struct{}
	wg         sync.WaitGroup
}

// NewIPDiscoveryScanner creates a new scanner.
func NewIPDiscoveryScanner(blocks []string, timeout time.Duration) *IPDiscoveryScanner {
	return &IPDiscoveryScanner{
		cidrBlocks: blocks,
		timeout:    timeout,
		results:    make(chan string, 100),
		stop:       make(chan struct{}),
	}
}

// Start starts parallel workers to scan.
func (s *IPDiscoveryScanner) Start(ctx context.Context, workers int) {
	for i := 0; i < workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx)
	}
}

// Stop stops the scanner.
func (s *IPDiscoveryScanner) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.stop:
		// already closed
	default:
		close(s.stop)
	}
	s.wg.Wait()
}

// Results returns the results channel.
func (s *IPDiscoveryScanner) Results() <-chan string {
	return s.results
}

func (s *IPDiscoveryScanner) worker(ctx context.Context) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stop:
			return
		default:
			ip := s.getRandomIP()
			if ip == "" {
				time.Sleep(10 * time.Millisecond)
				continue
			}

			address := net.JoinHostPort(ip, "443")
			conn, err := net.DialTimeout("tcp", address, s.timeout)
			if err == nil {
				conn.Close()
				select {
				case s.results <- ip:
				case <-ctx.Done():
					return
				case <-s.stop:
					return
				}
			}
		}
	}
}

func (s *IPDiscoveryScanner) getRandomIP() string {
	if len(s.cidrBlocks) == 0 {
		return ""
	}
	idx, err := randInt(len(s.cidrBlocks))
	if err != nil {
		return ""
	}
	cidr := s.cidrBlocks[idx]
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		if rawIP := net.ParseIP(cidr); rawIP != nil {
			return rawIP.String()
		}
		return ""
	}

	mask, _ := ipnet.Mask.Size()
	if mask >= 32 {
		return ip.String()
	}

	numIPs := 1 << (32 - mask)
	offset, err := randInt(numIPs)
	if err != nil {
		return ip.String()
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return ip.String()
	}

	ipInt := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
	randIPInt := ipInt + uint32(offset)

	randIP := net.IPv4(
		byte(randIPInt>>24),
		byte(randIPInt>>16),
		byte(randIPInt>>8),
		byte(randIPInt),
	)
	return randIP.String()
}

func randInt(max int) (int, error) {
	if max <= 0 {
		return 0, nil
	}
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(nBig.Int64()), nil
}
