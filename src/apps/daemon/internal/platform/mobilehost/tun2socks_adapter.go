package mobilehost

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/maybeknott/luminet/internal/platform/system/nat"
)

const socksAssociationHandshakeTimeout = 5 * time.Second

type udpAssociation struct {
	clientSrcAddr string
	socksTCP      net.Conn
	socksUDP      *net.UDPConn
	relayAddr     *net.UDPAddr
	lastUsed      time.Time
	mu            sync.Mutex
	closed        bool
}

type Tun2SocksAdapter struct {
	mu               sync.Mutex
	associations     map[string]*udpAssociation
	socksAddr        string
	tcpListener      *nat.TCP
	udpHandler       *nat.UDP
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	device           io.ReadWriteCloser
	dnsForwarderAddr string
	dnsWG            sync.WaitGroup
}

func StartTun2Socks(ctx context.Context, device io.ReadWriteCloser, tunAddr string, gatewayAddr string, socksAddr string) (*Tun2SocksAdapter, error) {
	return StartTun2SocksWithDNS(ctx, device, tunAddr, gatewayAddr, socksAddr, "")
}

// StartTun2SocksWithDNS starts userspace TUN translation and, when dnsForwarderAddr
// is non-empty, sends every UDP/53 query to that trusted local forwarder instead
// of allowing the SOCKS UDP relay to emit plaintext DNS directly. Replies are
// written back with the application's originally requested resolver as source.
func StartTun2SocksWithDNS(ctx context.Context, device io.ReadWriteCloser, tunAddr string, gatewayAddr string, socksAddr string, dnsForwarderAddr string) (*Tun2SocksAdapter, error) {
	// Parse network addresses
	prefix, err := netip.ParsePrefix(tunAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid TUN interface address: %w", err)
	}

	portal, err := netip.ParseAddr(gatewayAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid gateway portal address: %w", err)
	}

	tcpListener, udpHandler, err := nat.Start(device, prefix, portal)
	if err != nil {
		return nil, fmt.Errorf("failed to start userspace network translation: %w", err)
	}

	subCtx, cancel := context.WithCancel(ctx)
	adapter := &Tun2SocksAdapter{
		associations:     make(map[string]*udpAssociation),
		socksAddr:        socksAddr,
		tcpListener:      tcpListener,
		udpHandler:       udpHandler,
		ctx:              subCtx,
		cancel:           cancel,
		device:           device,
		dnsForwarderAddr: dnsForwarderAddr,
	}

	// Start TCP listener loop
	adapter.wg.Add(1)
	go func() {
		defer adapter.wg.Done()
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				return
			}
			go adapter.handleTCP(conn)
		}
	}()

	// Start UDP handler loop
	adapter.wg.Add(1)
	go func() {
		defer adapter.wg.Done()
		buf := make([]byte, 65535)
		for {
			n, srcAddr, dstAddr, err := udpHandler.ReadFrom(buf)
			if err != nil {
				return
			}
			packet := make([]byte, n)
			copy(packet, buf[:n])
			adapter.handleUDP(srcAddr, dstAddr, packet)
		}
	}()

	// Clean idle UDP associations
	adapter.wg.Add(1)
	go func() {
		defer adapter.wg.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-subCtx.Done():
				return
			case <-ticker.C:
				adapter.cleanIdleUDP()
			}
		}
	}()

	return adapter, nil
}

func (a *Tun2SocksAdapter) Close() error {
	a.cancel()
	_ = a.tcpListener.Close()
	_ = a.udpHandler.Close()

	a.mu.Lock()
	for _, assoc := range a.associations {
		assoc.close()
	}
	a.associations = make(map[string]*udpAssociation)
	a.mu.Unlock()

	a.wg.Wait()
	a.dnsWG.Wait()
	_ = a.device.Close()
	return nil
}

func (a *Tun2SocksAdapter) handleTCP(client net.Conn) {
	defer client.Close()

	dialer := net.Dialer{}
	socksConn, err := dialer.DialContext(a.ctx, "tcp", a.socksAddr)
	if err != nil {
		return
	}
	defer socksConn.Close()

	remoteAddr := client.RemoteAddr().(*net.TCPAddr)
	if err := socksConn.SetDeadline(socksHandshakeDeadline(a.ctx)); err != nil {
		return
	}
	err = socks5Handshake(socksConn, remoteAddr.IP, remoteAddr.Port)
	if err != nil {
		return
	}
	if err := socksConn.SetDeadline(time.Time{}); err != nil {
		return
	}

	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(socksConn, client)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(client, socksConn)
		errChan <- err
	}()

	select {
	case <-a.ctx.Done():
	case <-errChan:
	}
}

func (a *Tun2SocksAdapter) handleUDP(src net.Addr, dst net.Addr, payload []byte) {
	dstAddr, ok := dst.(*net.UDPAddr)
	if !ok {
		return
	}
	if dstAddr.Port == 53 && a.dnsForwarderAddr != "" {
		a.dnsWG.Add(1)
		go func() {
			defer a.dnsWG.Done()
			a.handleDNS(src, dstAddr, payload)
		}()
		return
	}

	assoc := a.getOrCreateUDPAssoc(src)
	if assoc == nil {
		return
	}

	assoc.mu.Lock()
	defer assoc.mu.Unlock()
	if assoc.closed {
		return
	}

	assoc.lastUsed = time.Now()

	// Wrap in SOCKS5 UDP request format
	dstIP := dstAddr.IP.To4()
	if dstIP == nil {
		return
	}

	header := make([]byte, 4+4+2)
	header[0] = 0x00 // RSV
	header[1] = 0x00 // RSV
	header[2] = 0x00 // FRAG
	header[3] = 0x01 // ATYP: IPv4
	copy(header[4:8], dstIP)
	binary.BigEndian.PutUint16(header[8:10], uint16(dstAddr.Port))

	packet := append(header, payload...)
	_, _ = assoc.socksUDP.WriteTo(packet, assoc.relayAddr)
}

func (a *Tun2SocksAdapter) handleDNS(src net.Addr, requestedResolver *net.UDPAddr, payload []byte) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(a.ctx, "udp", a.dnsForwarderAddr)
	if err != nil {
		return
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return
	}

	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	_, _ = a.udpHandler.WriteTo(buf[:n], requestedResolver, src)
}

func (a *Tun2SocksAdapter) getOrCreateUDPAssoc(src net.Addr) *udpAssociation {
	key := src.String()

	a.mu.Lock()
	assoc := a.associations[key]
	a.mu.Unlock()
	if assoc != nil {
		return assoc
	}

	newAssoc, err := a.createUDPAssoc(key)
	if err != nil {
		return nil
	}

	winner, installed := a.installUDPAssoc(key, newAssoc)
	if !installed {
		newAssoc.close()
		return winner
	}

	go a.readSocksUDP(newAssoc, src)
	return newAssoc
}

func (a *Tun2SocksAdapter) createUDPAssoc(key string) (*udpAssociation, error) {
	dialer := net.Dialer{Timeout: socksAssociationHandshakeTimeout}
	socksTCP, err := dialer.DialContext(a.ctx, "tcp", a.socksAddr)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*udpAssociation, error) {
		_ = socksTCP.Close()
		return nil, err
	}

	if err := socksTCP.SetDeadline(socksHandshakeDeadline(a.ctx)); err != nil {
		return fail(err)
	}
	if err := writeFull(socksTCP, []byte{0x05, 0x01, 0x00}); err != nil {
		return fail(err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(socksTCP, greeting); err != nil {
		return fail(err)
	}
	if greeting[0] != 0x05 || greeting[1] != 0x00 {
		return fail(fmt.Errorf("socks5 auth negotiation failed: %v", greeting))
	}

	if err := writeFull(socksTCP, []byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil {
		return fail(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(socksTCP, response); err != nil {
		return fail(err)
	}
	if response[0] != 0x05 || response[1] != 0x00 {
		return fail(fmt.Errorf("socks5 udp associate failed with status %d", response[1]))
	}

	relayAddr, err := readSocks5UDPRelay(socksTCP, response[3])
	if err != nil {
		return fail(err)
	}
	network := "udp4"
	if relayAddr.IP.To4() == nil {
		network = "udp6"
	}
	socksUDP, err := net.ListenUDP(network, nil)
	if err != nil {
		return fail(err)
	}
	if err := socksTCP.SetDeadline(time.Time{}); err != nil {
		_ = socksUDP.Close()
		return fail(err)
	}

	return &udpAssociation{
		clientSrcAddr: key,
		socksTCP:      socksTCP,
		socksUDP:      socksUDP,
		relayAddr:     relayAddr,
		lastUsed:      time.Now(),
	}, nil
}

func (a *Tun2SocksAdapter) installUDPAssoc(key string, candidate *udpAssociation) (*udpAssociation, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if existing := a.associations[key]; existing != nil {
		return existing, false
	}
	a.associations[key] = candidate
	return candidate, true
}

func (a *udpAssociation) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return
	}
	a.closed = true
	if a.socksTCP != nil {
		_ = a.socksTCP.Close()
	}
	if a.socksUDP != nil {
		_ = a.socksUDP.Close()
	}
}

func socksHandshakeDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(socksAssociationHandshakeTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	return deadline
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func readSocks5UDPRelay(r io.Reader, atyp byte) (*net.UDPAddr, error) {
	var relayIP net.IP
	switch atyp {
	case 0x01:
		buf := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		relayIP = net.IP(buf)
	case 0x04:
		buf := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		relayIP = net.IP(buf)
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return nil, err
		}
		if lenBuf[0] == 0 {
			return nil, fmt.Errorf("empty socks5 relay domain")
		}
		domainBuf := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(r, domainBuf); err != nil {
			return nil, err
		}
		ips, err := net.LookupIP(string(domainBuf))
		if err != nil || len(ips) == 0 {
			if err == nil {
				err = fmt.Errorf("no addresses returned")
			}
			return nil, fmt.Errorf("resolve socks5 relay %q: %w", string(domainBuf), err)
		}
		relayIP = ips[0]
	default:
		return nil, fmt.Errorf("unsupported socks5 relay atyp: %d", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: relayIP, Port: int(binary.BigEndian.Uint16(portBuf))}, nil
}

func (a *Tun2SocksAdapter) readSocksUDP(assoc *udpAssociation, src net.Addr) {
	buf := make([]byte, 65535)
	for {
		n, _, err := assoc.socksUDP.ReadFrom(buf)
		if err != nil {
			return
		}

		if n < 10 {
			continue // Invalid header
		}

		// SOCKS5 UDP Header: RSV(2) + FRAG(1) + ATYP(1) + IP(4) + Port(2)
		if buf[2] != 0x00 {
			continue // Fragments not supported
		}

		if buf[3] != 0x01 {
			continue // Only IPv4 is supported in this parser implementation
		}

		senderIP := net.IP(buf[4:8])
		senderPort := int(binary.BigEndian.Uint16(buf[8:10]))
		payload := buf[10:n]

		senderAddr := &net.UDPAddr{
			IP:   senderIP,
			Port: senderPort,
		}

		// Write packet back to the client via our userspace NAT stack
		_, _ = a.udpHandler.WriteTo(payload, senderAddr, src)
	}
}

func (a *Tun2SocksAdapter) cleanIdleUDP() {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	for key, assoc := range a.associations {
		assoc.mu.Lock()
		idle := now.Sub(assoc.lastUsed) > 60*time.Second
		assoc.mu.Unlock()
		if idle {
			assoc.close()
			delete(a.associations, key)
		}
	}
}

func socks5Handshake(conn net.Conn, targetIP net.IP, targetPort int) error {
	var err error
	if err := writeFull(conn, []byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	resp := make([]byte, 2)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		return err
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return fmt.Errorf("socks5 auth negotiation failed: %v", resp)
	}

	ip4 := targetIP.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 destination supported")
	}

	req := make([]byte, 4+4+2)
	req[0] = 0x05
	req[1] = 0x01
	req[2] = 0x00
	req[3] = 0x01
	copy(req[4:8], ip4)
	binary.BigEndian.PutUint16(req[8:10], uint16(targetPort))

	if err := writeFull(conn, req); err != nil {
		return err
	}

	repHeader := make([]byte, 4)
	_, err = io.ReadFull(conn, repHeader)
	if err != nil {
		return err
	}
	if repHeader[0] != 0x05 || repHeader[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed with status %d", repHeader[1])
	}

	var skipLen int
	switch repHeader[3] {
	case 0x01: // IPv4
		skipLen = 4 + 2
	case 0x03: // Domain
		domainLenBuf := make([]byte, 1)
		_, err = io.ReadFull(conn, domainLenBuf)
		if err != nil {
			return err
		}
		skipLen = int(domainLenBuf[0]) + 2
	case 0x04: // IPv6
		skipLen = 16 + 2
	default:
		return fmt.Errorf("unsupported atyp in socks5 response: %d", repHeader[3])
	}
	skipBuf := make([]byte, skipLen)
	_, err = io.ReadFull(conn, skipBuf)
	return err
}
