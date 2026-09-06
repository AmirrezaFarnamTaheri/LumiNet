package mobilecore

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// Common errors for TUN bridge operations.
var (
	ErrInvalidFd        = errors.New("invalid file descriptor")
	ErrDupFailed        = errors.New("file descriptor duplication failed")
	ErrSocksAuthFailed  = errors.New("upstream SOCKS5 authentication failed")
	ErrProxyStopped     = errors.New("fake DNS proxy is stopped")
	ErrMalformedPayload = errors.New("malformed socks5 or dns payload")
)

// DNSMapper provides thread-safe bidirectional mappings between hostnames
// and RFC 2544 FakeIP addresses (198.18.0.0/16).
type DNSMapper struct {
	mu           sync.RWMutex
	hostnameToIP map[string]string
	ipToHostname map[string]string
	counter      uint32
}

// NewDNSMapper constructs an empty DNSMapper initialized with counter 1.
func NewDNSMapper() *DNSMapper {
	return &DNSMapper{
		hostnameToIP: make(map[string]string),
		ipToHostname: make(map[string]string),
		counter:      1,
	}
}

// GetFakeIP returns an existing fake IP if mapped, or allocates a new IP in 198.18.0.0/16.
func (d *DNSMapper) GetFakeIP(hostname string) string {
	d.mu.Lock()
	defer d.mu.Unlock()

	if ip, exists := d.hostnameToIP[hostname]; exists {
		return ip
	}

	c := atomic.AddUint32(&d.counter, 1)
	if c > 65535 {
		atomic.StoreUint32(&d.counter, 1)
		c = 1
	}

	octet3 := byte(c >> 8)
	octet4 := byte(c & 0xFF)
	fakeIP := fmt.Sprintf("198.18.%d.%d", octet3, octet4)

	d.hostnameToIP[hostname] = fakeIP
	d.ipToHostname[fakeIP] = hostname
	return fakeIP
}

// GetHostname looks up the hostname corresponding to a fake IP.
func (d *DNSMapper) GetHostname(fakeIP string) (string, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	hostname, exists := d.ipToHostname[fakeIP]
	return hostname, exists
}

// Count returns the number of active domain-to-IP mappings.
func (d *DNSMapper) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.hostnameToIP)
}

// Reset clears all active mappings and resets the allocation counter.
func (d *DNSMapper) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hostnameToIP = make(map[string]string)
	d.ipToHostname = make(map[string]string)
	atomic.StoreUint32(&d.counter, 1)
}

// FakeDNSProxy intercepts SOCKS5 connections from local TUN, dynamically rewriting
// FakeIP destination addresses to domain names before upstream delivery.
type FakeDNSProxy struct {
	RealSocksAddr string
	SocksUser     string
	SocksPass     string
	LocalPort     int
	dnsMap        *DNSMapper
	listener      net.Listener
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
}

// NewFakeDNSProxy creates a new FakeDNSProxy pointing to the upstream real SOCKS5 address.
func NewFakeDNSProxy(realSocksAddr, socksUser, socksPass string, dnsMap *DNSMapper) *FakeDNSProxy {
	if dnsMap == nil {
		dnsMap = NewDNSMapper()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &FakeDNSProxy{
		RealSocksAddr: realSocksAddr,
		SocksUser:     socksUser,
		SocksPass:     socksPass,
		dnsMap:        dnsMap,
		ctx:           ctx,
		cancel:        cancel,
	}
}

// Start binds to an ephemeral loopback TCP port and starts accepting SOCKS5 connections.
func (p *FakeDNSProxy) Start() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	p.listener = l
	p.LocalPort = l.Addr().(*net.TCPAddr).Port

	p.wg.Add(1)
	go p.acceptLoop()

	return l.Addr().String(), nil
}

// Stop terminates the listener and waits for running goroutines to exit.
func (p *FakeDNSProxy) Stop() {
	p.cancel()
	if p.listener != nil {
		_ = p.listener.Close()
	}
	p.wg.Wait()
}

// DNSMap returns the underlying DNSMapper.
func (p *FakeDNSProxy) DNSMap() *DNSMapper {
	return p.dnsMap
}

func (p *FakeDNSProxy) acceptLoop() {
	defer p.wg.Done()
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			if p.ctx.Err() != nil {
				return
			}
			continue
		}
		p.wg.Add(1)
		go func(c net.Conn) {
			defer p.wg.Done()
			p.handleConnection(c)
		}(conn)
	}
}

func (p *FakeDNSProxy) dialRealSocks() (net.Conn, error) {
	realConn, err := net.Dial("tcp", p.RealSocksAddr)
	if err != nil {
		return nil, err
	}

	// SOCKS5 Greeting (RFC 1928)
	var greeting []byte
	if p.SocksUser != "" && p.SocksPass != "" {
		greeting = []byte{5, 2, 0, 2} // NO_AUTH and USER/PASS
	} else {
		greeting = []byte{5, 1, 0} // NO_AUTH
	}

	if _, err := realConn.Write(greeting); err != nil {
		_ = realConn.Close()
		return nil, err
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(realConn, resp); err != nil {
		_ = realConn.Close()
		return nil, err
	}

	if resp[0] != 5 {
		_ = realConn.Close()
		return nil, fmt.Errorf("upstream SOCKS5 version mismatch: %d", resp[0])
	}

	switch resp[1] {
	case 0:
		// NO_AUTH selected
		return realConn, nil
	case 2:
		// USERNAME/PASSWORD sub-negotiation (RFC 1929)
		if p.SocksUser == "" || p.SocksPass == "" {
			_ = realConn.Close()
			return nil, errors.New("upstream requires auth but credentials missing")
		}
		user := []byte(p.SocksUser)
		pass := []byte(p.SocksPass)
		if len(user) > 255 || len(pass) > 255 {
			_ = realConn.Close()
			return nil, errors.New("socks credentials exceed 255 bytes")
		}
		authReq := []byte{1, byte(len(user))}
		authReq = append(authReq, user...)
		authReq = append(authReq, byte(len(pass)))
		authReq = append(authReq, pass...)

		if _, err := realConn.Write(authReq); err != nil {
			_ = realConn.Close()
			return nil, err
		}

		authResp := make([]byte, 2)
		if _, err := io.ReadFull(realConn, authResp); err != nil {
			_ = realConn.Close()
			return nil, err
		}
		if authResp[1] != 0 {
			_ = realConn.Close()
			return nil, fmt.Errorf("%w: status %d", ErrSocksAuthFailed, authResp[1])
		}
		return realConn, nil
	default:
		_ = realConn.Close()
		return nil, fmt.Errorf("upstream selected unsupported auth method %d", resp[1])
	}
}

func (p *FakeDNSProxy) handleConnection(conn net.Conn) {
	defer conn.Close()

	// SOCKS5 client greeting
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != 5 {
		return
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	// Client authentication reply: NO_AUTH
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}

	// SOCKS5 Request
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return
	}

	cmd := reqHeader[1]
	atyp := reqHeader[3]

	var targetAddr []byte
	switch atyp {
	case 1: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		targetAddr = ip
	case 3: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		dom := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, dom); err != nil {
			return
		}
		targetAddr = append(lenBuf, dom...)
	case 4: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		targetAddr = ip
	default:
		return
	}

	targetPort := make([]byte, 2)
	if _, err := io.ReadFull(conn, targetPort); err != nil {
		return
	}

	// FakeDNS Interception for TCP CONNECT
	if cmd == 1 && atyp == 1 {
		ipStr := net.IP(targetAddr).String()
		if hostname, ok := p.dnsMap.GetHostname(ipStr); ok {
			atyp = 3
			l := byte(len(hostname))
			targetAddr = append([]byte{l}, []byte(hostname)...)
		}
	}

	if cmd == 3 { // UDP ASSOCIATE
		p.handleUDPAssociate(conn, atyp, targetAddr, targetPort)
		return
	}

	// Dial Real SOCKS
	realConn, err := p.dialRealSocks()
	if err != nil {
		_, _ = conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer realConn.Close()

	req := []byte{5, 1, 0, atyp}
	req = append(req, targetAddr...)
	req = append(req, targetPort...)
	if _, err := realConn.Write(req); err != nil {
		return
	}

	replyHeader := make([]byte, 4)
	if _, err := io.ReadFull(realConn, replyHeader); err != nil {
		return
	}
	if _, err := conn.Write(replyHeader); err != nil {
		return
	}

	var bndAddr []byte
	switch replyHeader[3] {
	case 1:
		bndAddr = make([]byte, 4)
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(realConn, l); err != nil {
			return
		}
		bndAddr = make([]byte, l[0])
		bndAddr = append(l, bndAddr...)
	case 4:
		bndAddr = make([]byte, 16)
	}

	if len(bndAddr) > 0 {
		if _, err := io.ReadFull(realConn, bndAddr); err != nil {
			return
		}
		if _, err := conn.Write(bndAddr); err != nil {
			return
		}
	}

	bndPort := make([]byte, 2)
	if _, err := io.ReadFull(realConn, bndPort); err != nil {
		return
	}
	if _, err := conn.Write(bndPort); err != nil {
		return
	}

	go func() {
		_, _ = io.Copy(realConn, conn)
	}()
	_, _ = io.Copy(conn, realConn)
}

func (p *FakeDNSProxy) handleUDPAssociate(tcpConn net.Conn, atyp byte, targetAddr []byte, targetPort []byte) {
	realConn, err := p.dialRealSocks()
	if err != nil {
		_, _ = tcpConn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer realConn.Close()

	req := []byte{5, 3, 0, atyp}
	req = append(req, targetAddr...)
	req = append(req, targetPort...)
	if _, err := realConn.Write(req); err != nil {
		return
	}

	replyHeader := make([]byte, 4)
	if _, err := io.ReadFull(realConn, replyHeader); err != nil {
		return
	}

	var bndAddr []byte
	switch replyHeader[3] {
	case 1:
		bndAddr = make([]byte, 4)
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(realConn, l); err != nil {
			return
		}
		dom := make([]byte, l[0])
		if _, err := io.ReadFull(realConn, dom); err != nil {
			return
		}
		bndAddr = append(l, dom...)
	case 4:
		bndAddr = make([]byte, 16)
	}

	if len(bndAddr) > 0 {
		if _, err := io.ReadFull(realConn, bndAddr); err != nil {
			return
		}
	}

	bndPortBuf := make([]byte, 2)
	if _, err := io.ReadFull(realConn, bndPortBuf); err != nil {
		return
	}

	var realUdpAddr *net.UDPAddr
	if replyHeader[3] == 1 {
		realUdpAddr = &net.UDPAddr{IP: net.IP(bndAddr), Port: int(binary.BigEndian.Uint16(bndPortBuf))}
	}
	if realUdpAddr != nil && realUdpAddr.IP.IsUnspecified() {
		host, _, _ := net.SplitHostPort(p.RealSocksAddr)
		realUdpAddr.IP = net.ParseIP(host)
	}

	localUdp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_, _ = tcpConn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer localUdp.Close()

	localPort := localUdp.LocalAddr().(*net.UDPAddr).Port

	reply := []byte{5, 0, 0, 1, 127, 0, 0, 1}
	pBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(pBuf, uint16(localPort))
	reply = append(reply, pBuf...)
	if _, err := tcpConn.Write(reply); err != nil {
		return
	}

	go func() {
		buf := make([]byte, 65535)
		var tun2socksAddr *net.UDPAddr
		for {
			n, rAddr, err := localUdp.ReadFromUDP(buf)
			if err != nil {
				return
			}

			if realUdpAddr != nil && rAddr.IP.Equal(realUdpAddr.IP) && rAddr.Port == realUdpAddr.Port {
				if tun2socksAddr != nil {
					_, _ = localUdp.WriteToUDP(buf[:n], tun2socksAddr)
				}
				continue
			}

			tun2socksAddr = rAddr
			if n < 4 || buf[2] != 0 {
				continue
			}

			reqAtyp := buf[3]
			var offset int
			var tPort uint16

			switch reqAtyp {
			case 1:
				offset = 10
				if n < offset {
					continue
				}
				tPort = binary.BigEndian.Uint16(buf[8:10])
			case 3:
				l := int(buf[4])
				offset = 5 + l + 2
				if n < offset {
					continue
				}
				tPort = binary.BigEndian.Uint16(buf[5+l : offset])
			case 4:
				offset = 22
				if n < offset {
					continue
				}
				tPort = binary.BigEndian.Uint16(buf[20:22])
			default:
				continue
			}

			if tPort == 53 {
				dnsQuery := buf[offset:n]
				hostname := ParseDNSQuery(dnsQuery)
				if hostname != "" {
					fakeIP := p.dnsMap.GetFakeIP(hostname)
					resp := BuildDNSResponse(dnsQuery, fakeIP)
					if resp != nil {
						fullResp := append(buf[:offset], resp...)
						_, _ = localUdp.WriteToUDP(fullResp, rAddr)
					}
				}
				continue
			}

			if realUdpAddr != nil {
				_, _ = localUdp.WriteToUDP(buf[:n], realUdpAddr)
			}
		}
	}()

	// Keep TCP association alive until client disconnects
	_, _ = io.Copy(io.Discard, tcpConn)
}

// ParseDNSQuery extracts the domain name from a raw DNS wire format query.
func ParseDNSQuery(query []byte) string {
	if len(query) < 12 {
		return ""
	}
	pos := 12
	var labels []string
	for pos < len(query) {
		length := int(query[pos])
		if length == 0 {
			break
		}
		if length > 63 || pos+1+length > len(query) {
			return ""
		}
		pos++
		labels = append(labels, string(query[pos:pos+length]))
		pos += length
	}
	if len(labels) == 0 {
		return ""
	}
	var hostname string
	for i, label := range labels {
		if i > 0 {
			hostname += "."
		}
		hostname += label
	}
	return hostname
}

// BuildDNSResponse synthesizes an A-record DNS response pointing to fakeIP.
func BuildDNSResponse(query []byte, fakeIP string) []byte {
	if len(query) < 12 {
		return nil
	}
	response := make([]byte, len(query)+16)
	copy(response, query)

	flags := binary.BigEndian.Uint16(response[2:4])
	flags |= 0x8400 // Standard query response, Authoritative Answer
	binary.BigEndian.PutUint16(response[2:4], flags)
	binary.BigEndian.PutUint16(response[6:8], 1) // 1 Answer RRs

	pos := len(query)
	// Pointer to question name (offset 12 = 0x0C)
	response[pos] = 0xC0
	response[pos+1] = 0x0C
	pos += 2

	binary.BigEndian.PutUint16(response[pos:pos+2], 1) // Type A
	binary.BigEndian.PutUint16(response[pos+2:pos+4], 1) // Class IN
	pos += 4

	binary.BigEndian.PutUint32(response[pos:pos+4], 60) // TTL 60 seconds
	pos += 4

	binary.BigEndian.PutUint16(response[pos:pos+2], 4) // Data length 4
	pos += 2

	ip := net.ParseIP(fakeIP).To4()
	if ip == nil {
		return nil
	}
	copy(response[pos:pos+4], ip)
	pos += 4

	return response[:pos]
}

// DupFd provides safe file descriptor duplication to avoid Android double-close faults.
func DupFd(fd int) (int, error) {
	if fd < 0 {
		return -1, ErrInvalidFd
	}
	return dupFdPlatform(fd)
}
