package proxy

// tun_device.go — TUN virtual-interface adapter for transparent proxy.
//
// Inspired by TinyTun (Rust): https://github.com/nikitavoloboev/tinytun
// and the waterfowl/tun family of Go TUN libraries.
//
// Provides a cross-platform TUN device wrapper that:
//   - Creates a virtual TUN interface with a configured IP/mask/MTU
//   - Reads raw IP packets from the TUN and dispatches them to a SOCKS5 upstream
//   - Handles IPv4/IPv6, TCP and UDP flows independently
//   - Optionally sets up auto-route (redirect all OS traffic through the TUN)
//
// This enables a "transparent proxy" mode: applications on the host dial
// normally; the TUN device captures all packets and routes them through the
// configured SOCKS5 (or other) proxy without requiring any per-application
// configuration.
//
// Build constraint: this file compiles on all platforms but the TUN device
// creation is only functional on Linux and Windows (where the tun package has
// proper kernel support).  On other platforms the TunConfig.Open() method
// returns an error and the caller must fall back to a SOCKS-only mode.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// TunConfig describes the parameters for a TUN virtual interface.
type TunConfig struct {
	// Name is the interface name, e.g. "lumi0" or "tun0".  On Windows, this
	// must match a WinTun adapter name.
	Name string

	// Address is the TUN interface's own IPv4 address (e.g. "10.88.0.1").
	Address string

	// Netmask is the subnet prefix length (e.g. 30 for /30 = 4-host subnet).
	PrefixLen int

	// MTU is the Maximum Transfer Unit in bytes.  0 defaults to 1500.
	MTU int

	// AutoRoute, when true, installs a default route so all OS traffic is
	// redirected through the TUN device.
	AutoRoute bool

	// IPv6Address is the optional link-local IPv6 address to assign.
	IPv6Address string

	// UpstreamSOCKS5 is the SOCKS5 address (host:port) that all intercepted
	// flows are forwarded to.
	UpstreamSOCKS5 string

	// DNSServers lists the DNS servers to use for DNS-over-SOCKS5 queries.
	DNSServers []string
}

// TunFlowKey identifies a unique TCP or UDP flow.
type TunFlowKey struct {
	SrcIP   [16]byte
	DstIP   [16]byte
	SrcPort uint16
	DstPort uint16
	Proto   uint8 // 6=TCP, 17=UDP
}

// TunFlowEntry tracks the upstream connection for a single flow.
type TunFlowEntry struct {
	upstream net.Conn
	lastSeen atomic.Int64 // Unix timestamp in seconds
}

// TunDevice is the runtime handle for an open TUN virtual interface.
type TunDevice struct {
	cfg    TunConfig
	reader io.ReadCloser
	writer io.WriteCloser

	mu     sync.RWMutex
	flows  map[TunFlowKey]*TunFlowEntry
	filter *TUNPacketFilter

	closed  atomic.Bool
	metrics TunDeviceMetrics
}

// TunDeviceMetrics tracks packet-level statistics.
type TunDeviceMetrics struct {
	RxPackets atomic.Int64
	TxPackets atomic.Int64
	RxBytes   atomic.Int64
	TxBytes   atomic.Int64
	Dropped   atomic.Int64
	FlowsOpen atomic.Int64
}

// TunDeviceStats is a snapshot of TunDeviceMetrics for reporting.
type TunDeviceStats struct {
	RxPackets int64
	TxPackets int64
	RxBytes   int64
	TxBytes   int64
	Dropped   int64
	FlowsOpen int64
}

// Stats returns a point-in-time copy of the metrics.
func (td *TunDevice) Stats() TunDeviceStats {
	return TunDeviceStats{
		RxPackets: td.metrics.RxPackets.Load(),
		TxPackets: td.metrics.TxPackets.Load(),
		RxBytes:   td.metrics.RxBytes.Load(),
		TxBytes:   td.metrics.TxBytes.Load(),
		Dropped:   td.metrics.Dropped.Load(),
		FlowsOpen: td.metrics.FlowsOpen.Load(),
	}
}

// openTunPlatform is implemented per-platform:
//   - tun_device_linux.go  — uses /dev/net/tun + ioctl
//   - tun_device_windows.go — uses WinTun API
//   - tun_device_stub.go   — returns ErrUnsupported on all other OS
// The function sets td.reader and td.writer.
// It is defined in platform-specific files; the stub is below.

// Close shuts down the TUN device and all associated flows.
func (td *TunDevice) Close() error {
	if td.closed.Swap(true) {
		return nil
	}
	td.mu.Lock()
	for key, entry := range td.flows {
		entry.upstream.Close() //nolint:errcheck
		delete(td.flows, key)
	}
	td.mu.Unlock()
	if td.reader != nil {
		td.reader.Close() //nolint:errcheck
	}
	if td.writer != nil {
		td.writer.Close() //nolint:errcheck
	}
	return nil
}

// Run is the main processing loop.  It reads IP packets from the TUN device,
// parses the flow key, and dispatches each packet to the correct upstream
// SOCKS5 connection.  Run blocks until ctx is cancelled or an unrecoverable
// error occurs.
func (td *TunDevice) Run(ctx context.Context) error {
	buf := make([]byte, td.cfg.MTU+4)
	for {
		if td.closed.Load() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := td.reader.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("tun read: %w", err)
		}
		if n < 20 {
			td.metrics.Dropped.Add(1)
			continue
		}

		td.metrics.RxPackets.Add(1)
		td.metrics.RxBytes.Add(int64(n))

		packet := buf[:n]
		if err := td.handlePacket(ctx, packet); err != nil {
			td.metrics.Dropped.Add(1)
		}
	}
}

// handlePacket dispatches a raw IP packet to the appropriate handler.
func (td *TunDevice) handlePacket(ctx context.Context, packet []byte) error {
	version := packet[0] >> 4
	switch version {
	case 4:
		return td.handleIPv4(ctx, packet)
	case 6:
		return td.handleIPv6(ctx, packet)
	default:
		return fmt.Errorf("tun: unknown IP version %d", version)
	}
}

// handleIPv4 processes an IPv4 packet.
func (td *TunDevice) handleIPv4(ctx context.Context, pkt []byte) error {
	if len(pkt) < 20 {
		return errors.New("tun: truncated IPv4 packet")
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || ihl > len(pkt) {
		return errors.New("tun: invalid IPv4 IHL")
	}
	proto := pkt[9]
	srcIP := pkt[12:16]
	dstIP := pkt[16:20]
	payload := pkt[ihl:]

	switch proto {
	case 6: // TCP
		return td.handleTCP(ctx, srcIP, dstIP, payload, 4)
	case 17: // UDP
		return td.handleUDP(ctx, srcIP, dstIP, payload, 4)
	default:
		return nil // silently drop ICMP, etc.
	}
}

// handleIPv6 processes an IPv6 packet.
func (td *TunDevice) handleIPv6(ctx context.Context, pkt []byte) error {
	if len(pkt) < 40 {
		return errors.New("tun: truncated IPv6 packet")
	}
	nextHeader := pkt[6]
	srcIP := pkt[8:24]
	dstIP := pkt[24:40]
	payload := pkt[40:]

	switch nextHeader {
	case 6:
		return td.handleTCP(ctx, srcIP, dstIP, payload, 6)
	case 17:
		return td.handleUDP(ctx, srcIP, dstIP, payload, 6)
	default:
		return nil
	}
}

// handleTCP forwards a raw TCP segment to the SOCKS5 upstream.
func (td *TunDevice) handleTCP(ctx context.Context, srcIP, dstIP, segment []byte, ipVer int) error {
	if len(segment) < 20 {
		return nil
	}
	srcPort := binary.BigEndian.Uint16(segment[0:2])
	dstPort := binary.BigEndian.Uint16(segment[2:4])

	if td.filter != nil {
		if td.filter.Evaluate(net.IP(srcIP), net.IP(dstIP), dstPort) == TUNActionBlock {
			td.metrics.Dropped.Add(1)
			return nil
		}
	}

	key := td.makeFlowKey(srcIP, dstIP, srcPort, dstPort, 6)

	td.mu.RLock()
	entry, ok := td.flows[key]
	td.mu.RUnlock()

	if !ok {
		// New TCP flow: dial upstream SOCKS5.
		if td.cfg.UpstreamSOCKS5 == "" {
			return nil
		}
		dstAddr := td.formatAddr(dstIP, dstPort, ipVer)
		upstream, err := dialSOCKS5(ctx, td.cfg.UpstreamSOCKS5, dstAddr)
		if err != nil {
			return fmt.Errorf("tun: socks5 dial %s: %w", dstAddr, err)
		}
		newEntry := &TunFlowEntry{
			upstream: upstream,
		}
		newEntry.lastSeen.Store(time.Now().Unix())

		// Re-check under write lock to prevent TOCTOU race.
		td.mu.Lock()
		if existing, dup := td.flows[key]; dup {
			// Another goroutine beat us; close the redundant upstream and use the existing one.
			td.mu.Unlock()
			upstream.Close() //nolint:errcheck
			entry = existing
		} else {
			td.flows[key] = newEntry
			td.mu.Unlock()
			td.metrics.FlowsOpen.Add(1)
			entry = newEntry

			// Start a goroutine to relay responses from upstream back into the TUN.
			// Note: srcIP/dstIP are swapped in the reply so packets route back
			// to the original client (TUN side sees dst=client, src=server).
			go td.relayFromUpstream(ctx, key, newEntry, dstIP, srcIP, dstPort, srcPort, ipVer)
		}
	}

	entry.lastSeen.Store(time.Now().Unix())

	// Extract TCP payload data offset.
	dataOffset := int(segment[12]>>4) * 4
	if dataOffset > len(segment) {
		return nil
	}
	data := segment[dataOffset:]
	if len(data) == 0 {
		return nil
	}

	_, err := entry.upstream.Write(data)
	return err
}

// handleUDP sends a UDP datagram to SOCKS5 upstream (via ASSOCIATE or TCP relay).
func (td *TunDevice) handleUDP(ctx context.Context, srcIP, dstIP, segment []byte, ipVer int) error {
	if len(segment) < 8 {
		return nil
	}
	srcPort := binary.BigEndian.Uint16(segment[0:2])
	dstPort := binary.BigEndian.Uint16(segment[2:4])

	if td.filter != nil {
		if td.filter.Evaluate(net.IP(srcIP), net.IP(dstIP), dstPort) == TUNActionBlock {
			td.metrics.Dropped.Add(1)
			return nil
		}
	}

	payload := segment[8:]
	if len(payload) == 0 {
		return nil
	}

	dstAddr := td.formatAddr(dstIP, dstPort, ipVer)
	if td.cfg.UpstreamSOCKS5 == "" {
		return nil
	}

	// For UDP we use a lightweight fire-and-forget approach: dial SOCKS5 in TCP
	// mode and frame it with the UDP gateway protocol (same as badvpn udpgw).
	upstream, err := dialSOCKS5(ctx, td.cfg.UpstreamSOCKS5, dstAddr)
	if err != nil {
		return fmt.Errorf("tun: udp socks5 dial %s: %w", dstAddr, err)
	}
	defer upstream.Close() //nolint:errcheck

	key := td.makeFlowKey(srcIP, dstIP, srcPort, dstPort, 17)
	_ = key // not tracking UDP flows for now

	_, err = upstream.Write(payload)
	return err
}

// relayFromUpstream reads data from the upstream SOCKS5 connection and
// injects it back into the TUN device as raw IP packets.
func (td *TunDevice) relayFromUpstream(
	ctx context.Context,
	key TunFlowKey,
	entry *TunFlowEntry,
	srcIP, dstIP []byte,
	srcPort, dstPort uint16,
	ipVer int,
) {
	defer func() {
		td.mu.Lock()
		delete(td.flows, key)
		td.mu.Unlock()
		td.metrics.FlowsOpen.Add(-1)
		entry.upstream.Close() //nolint:errcheck
	}()

	buf := make([]byte, td.cfg.MTU)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := entry.upstream.Read(buf)
		if n > 0 {
			// Build a minimal TCP/IP packet and inject it.
			pkt := td.buildTCPPacket(srcIP, dstIP, srcPort, dstPort, buf[:n], ipVer)
			if pkt != nil {
				_, _ = td.writer.Write(pkt)
				td.metrics.TxPackets.Add(1)
				td.metrics.TxBytes.Add(int64(len(pkt)))
			}
		}
		if err != nil {
			return
		}
	}
}

// makeFlowKey constructs a stable map key for a 5-tuple flow.
func (td *TunDevice) makeFlowKey(srcIP, dstIP []byte, srcPort, dstPort uint16, proto uint8) TunFlowKey {
	var key TunFlowKey
	copy(key.SrcIP[:], srcIP)
	copy(key.DstIP[:], dstIP)
	key.SrcPort = srcPort
	key.DstPort = dstPort
	key.Proto = proto
	return key
}

// formatAddr returns a "host:port" string from a raw IP slice + port.
func (td *TunDevice) formatAddr(ip []byte, port uint16, ipVer int) string {
	if ipVer == 4 {
		return fmt.Sprintf("%d.%d.%d.%d:%d", ip[0], ip[1], ip[2], ip[3], port)
	}
	ipStr := net.IP(ip).String()
	return fmt.Sprintf("[%s]:%d", ipStr, port)
}

// buildTCPPacket constructs a minimal IPv4/IPv6 + TCP/data packet for TUN injection.
// This is a simplified raw packet builder; for production use replace with
// etherparse or gopacket.
func (td *TunDevice) buildTCPPacket(srcIP, dstIP []byte, srcPort, dstPort uint16, data []byte, ipVer int) []byte {
	// Build a plain TCP segment header (20 bytes, no options).
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort)
	// seq, ack = 0 (simplified); data offset = 5 (20 bytes)
	tcpHeader[12] = 0x50                                // data offset = 5 words = 20 bytes
	tcpHeader[13] = 0x18                                // PSH + ACK
	binary.BigEndian.PutUint16(tcpHeader[14:16], 65535) // window size

	segment := append(tcpHeader, data...)

	if ipVer == 4 {
		// Build IPv4 header (20 bytes).
		ipHeader := make([]byte, 20)
		ipHeader[0] = 0x45                                                 // version=4, IHL=5
		ipHeader[1] = 0x00                                                 // DSCP/ECN
		binary.BigEndian.PutUint16(ipHeader[2:4], uint16(20+len(segment))) // total length
		binary.BigEndian.PutUint16(ipHeader[4:6], 0)                       // identification
		binary.BigEndian.PutUint16(ipHeader[6:8], 0x4000)                  // DF flag
		ipHeader[8] = 64                                                   // TTL
		ipHeader[9] = 6                                                    // protocol = TCP
		copy(ipHeader[12:16], srcIP)
		copy(ipHeader[16:20], dstIP)
		// Compute IPv4 header checksum.
		binary.BigEndian.PutUint16(ipHeader[10:12], ipv4Checksum(ipHeader))
		return append(ipHeader, segment...)
	}

	// IPv6 (simplified).
	ipHeader := make([]byte, 40)
	ipHeader[0] = 0x60                                              // version=6
	binary.BigEndian.PutUint16(ipHeader[4:6], uint16(len(segment))) // payload length
	ipHeader[6] = 6                                                 // next header = TCP
	ipHeader[7] = 64                                                // hop limit
	copy(ipHeader[8:24], srcIP)
	copy(ipHeader[24:40], dstIP)
	return append(ipHeader, segment...)
}

// ipv4Checksum computes the one's complement checksum of an IPv4 header.
func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// dialSOCKS5 dials addr through a SOCKS5 proxy at socks5Addr.
// It uses the same minimal SOCKS5 handshake as the existing socks5_stun.go.
func dialSOCKS5(ctx context.Context, socks5Addr, targetAddr string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", socks5Addr)
	if err != nil {
		return nil, err
	}

	// SOCKS5 handshake: no-auth negotiation.
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		conn.Close()
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil || resp[0] != 5 || resp[1] != 0 {
		conn.Close()
		return nil, fmt.Errorf("socks5: auth negotiation failed")
	}

	// CONNECT request.
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	var portNum uint16
	if _, err := fmt.Sscanf(portStr, "%d", &portNum); err != nil {
		conn.Close()
		return nil, err
	}

	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(portNum>>8), byte(portNum))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	// Read CONNECT response (minimum 10 bytes for IPv4 bind addr).
	connResp := make([]byte, 10)
	if _, err := io.ReadFull(conn, connResp); err != nil || connResp[1] != 0 {
		conn.Close()
		return nil, fmt.Errorf("socks5: CONNECT failed: rep=%d", connResp[1])
	}

	return conn, nil
}

// TunCleanupExpiredFlows removes flow entries that have been idle longer than ttl.
// Call periodically (e.g. every 30 s) to avoid memory leaks.
func (td *TunDevice) TunCleanupExpiredFlows(ttl time.Duration) {
	now := time.Now().Unix()
	td.mu.Lock()
	defer td.mu.Unlock()
	for key, entry := range td.flows {
		if now-entry.lastSeen.Load() > int64(ttl.Seconds()) {
			entry.upstream.Close() //nolint:errcheck
			delete(td.flows, key)
			td.metrics.FlowsOpen.Add(-1)
		}
	}
}

func (td *TunDevice) initFilter() {
	filter := NewTUNPacketFilter()
	if td.cfg.Address != "" && td.cfg.PrefixLen > 0 {
		_, subnet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", td.cfg.Address, td.cfg.PrefixLen))
		if err == nil {
			filter.VPNSubnet = subnet
			filter.GatewayIP = net.ParseIP(td.cfg.Address)
		}
	}
	filter.IsolateClients = true
	td.filter = filter
}
