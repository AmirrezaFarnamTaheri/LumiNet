package proxy

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// PacketInjector defines the interface for raw TCP packet capture and wrong-sequence injection.
type PacketInjector interface {
	Start(ctx context.Context, listenPort int) error
	Stop() error
	IsRunning() bool
}

// MutateIPv4Source spoof-rewrites the source IP of an IPv4 packet, recalculating checksums.
func MutateIPv4Source(packet []byte, decoyIP net.IP) []byte {
	if len(packet) < 20 {
		return packet
	}

	// Check IPv4 version
	version := packet[0] >> 4
	if version != 4 {
		return packet
	}

	ihl := int(packet[0]&0x0F) * 4
	if len(packet) < ihl {
		return packet
	}

	// Rewrite source IP (bytes 12-15)
	decoyBytes := decoyIP.To4()
	if decoyBytes == nil {
		return packet
	}
	copy(packet[12:16], decoyBytes)

	// Recompute IPv4 Header Checksum (bytes 10-11)
	packet[10] = 0
	packet[11] = 0
	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[:ihl]))

	// Recompute TCP/UDP Checksum if applicable
	proto := packet[9]
	if proto == 6 && len(packet) >= ihl+20 { // TCP
		tcpLen := len(packet) - ihl
		tcpSegment := packet[ihl:]
		// Zero the checksum field before recomputing
		tcpSegment[16] = 0
		tcpSegment[17] = 0

		srcIP := packet[12:16]
		dstIP := packet[16:20]

		// Build pseudo-header + TCP segment for checksum
		pseudo := make([]byte, 12+tcpLen)
		copy(pseudo[0:4], srcIP)
		copy(pseudo[4:8], dstIP)
		pseudo[8] = 0
		pseudo[9] = 6
		binary.BigEndian.PutUint16(pseudo[10:], uint16(tcpLen))
		copy(pseudo[12:], tcpSegment)

		binary.BigEndian.PutUint16(tcpSegment[16:18], internetChecksum(pseudo))
	} else if proto == 17 && len(packet) >= ihl+8 { // UDP
		udpLen := len(packet) - ihl
		udpSegment := packet[ihl:]
		udpSegment[6] = 0
		udpSegment[7] = 0

		srcIP := packet[12:16]
		dstIP := packet[16:20]

		pseudo := make([]byte, 12+udpLen)
		copy(pseudo[0:4], srcIP)
		copy(pseudo[4:8], dstIP)
		pseudo[8] = 0
		pseudo[9] = 17
		binary.BigEndian.PutUint16(pseudo[10:], uint16(udpLen))
		copy(pseudo[12:], udpSegment)

		binary.BigEndian.PutUint16(udpSegment[6:8], internetChecksum(pseudo))
	}

	return packet
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

type connSeqKey struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

type connSeqEntry struct {
	Seq        uint32
	ObservedAt time.Time
}

const (
	connSeqTTL         = 30 * time.Second
	maxConnSeqRegistry = 4096
)

var (
	connSeqRegistry = make(map[connSeqKey]connSeqEntry)
	connSeqMu       sync.Mutex
)

func canonicalConnSeqIP(ip net.IP) (string, bool) {
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), true
	}
	if v6 := ip.To16(); v6 != nil {
		return v6.String(), true
	}
	return "", false
}

func makeConnSeqKey(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) (connSeqKey, bool) {
	src, ok := canonicalConnSeqIP(srcIP)
	if !ok {
		return connSeqKey{}, false
	}
	dst, ok := canonicalConnSeqIP(dstIP)
	if !ok {
		return connSeqKey{}, false
	}
	return connSeqKey{SrcIP: src, SrcPort: srcPort, DstIP: dst, DstPort: dstPort}, true
}

func pruneConnSeqRegistryLocked(now time.Time) {
	for key, entry := range connSeqRegistry {
		if now.Sub(entry.ObservedAt) >= connSeqTTL {
			delete(connSeqRegistry, key)
		}
	}
	for len(connSeqRegistry) >= maxConnSeqRegistry {
		var oldestKey connSeqKey
		var oldest time.Time
		first := true
		for key, entry := range connSeqRegistry {
			if first || entry.ObservedAt.Before(oldest) {
				oldestKey = key
				oldest = entry.ObservedAt
				first = false
			}
		}
		if first {
			break
		}
		delete(connSeqRegistry, oldestKey)
	}
}

// RegisterConnSeq records a captured SYN sequence number for one exact network
// four-tuple. Entries are bounded and expire quickly so unrelated or stale
// handshakes cannot become injection authority for a later connection.
func RegisterConnSeq(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, seq uint32) {
	registerConnSeqAt(srcIP, srcPort, dstIP, dstPort, seq, time.Now())
}

func registerConnSeqAt(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, seq uint32, observedAt time.Time) {
	key, ok := makeConnSeqKey(srcIP, srcPort, dstIP, dstPort)
	if !ok {
		return
	}
	connSeqMu.Lock()
	defer connSeqMu.Unlock()
	pruneConnSeqRegistryLocked(observedAt)
	connSeqRegistry[key] = connSeqEntry{Seq: seq, ObservedAt: observedAt}
}

// GetConnSeq returns a still-fresh sequence observation without consuming it.
func GetConnSeq(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) (uint32, bool) {
	return getConnSeqAt(srcIP, srcPort, dstIP, dstPort, time.Now(), false)
}

// TakeConnSeq atomically consumes a still-fresh sequence observation. Injection
// code should prefer this to a separate Get+Clear pair so one SYN cannot be
// reused by concurrent callers.
func TakeConnSeq(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) (uint32, bool) {
	return getConnSeqAt(srcIP, srcPort, dstIP, dstPort, time.Now(), true)
}

func getConnSeqAt(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, now time.Time, consume bool) (uint32, bool) {
	key, ok := makeConnSeqKey(srcIP, srcPort, dstIP, dstPort)
	if !ok {
		return 0, false
	}
	connSeqMu.Lock()
	defer connSeqMu.Unlock()
	pruneConnSeqRegistryLocked(now)
	entry, found := connSeqRegistry[key]
	if !found {
		return 0, false
	}
	if consume {
		delete(connSeqRegistry, key)
	}
	return entry.Seq, true
}

// ClearConnSeq removes one exact four-tuple observation.
func ClearConnSeq(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) {
	key, ok := makeConnSeqKey(srcIP, srcPort, dstIP, dstPort)
	if !ok {
		return
	}
	connSeqMu.Lock()
	defer connSeqMu.Unlock()
	delete(connSeqRegistry, key)
}

// parseTCPHandshake parses a raw IPv4/IPv6 TCP packet and returns the exact
// four-tuple plus sequence number when the packet is an outbound SYN (SYN set,
// ACK clear). IPv6 extension headers are deliberately not guessed here.
func parseTCPHandshake(packet []byte) (srcIP, dstIP net.IP, srcPort, dstPort uint16, seq uint32, isSyn bool) {
	if len(packet) < 20 {
		return nil, nil, 0, 0, 0, false
	}

	var tcpOffset int
	switch packet[0] >> 4 {
	case 4:
		ihl := int(packet[0]&0x0F) * 4
		if ihl < 20 || len(packet) < ihl+20 || packet[9] != 6 {
			return nil, nil, 0, 0, 0, false
		}
		srcIP = append(net.IP(nil), packet[12:16]...)
		dstIP = append(net.IP(nil), packet[16:20]...)
		tcpOffset = ihl
	case 6:
		if len(packet) < 40+20 || packet[6] != 6 {
			return nil, nil, 0, 0, 0, false
		}
		srcIP = append(net.IP(nil), packet[8:24]...)
		dstIP = append(net.IP(nil), packet[24:40]...)
		tcpOffset = 40
	default:
		return nil, nil, 0, 0, 0, false
	}

	tcpSegment := packet[tcpOffset:]
	srcPort = binary.BigEndian.Uint16(tcpSegment[0:2])
	dstPort = binary.BigEndian.Uint16(tcpSegment[2:4])
	seq = binary.BigEndian.Uint32(tcpSegment[4:8])
	flags := tcpSegment[13]
	isSyn = flags&0x02 != 0 && flags&0x10 == 0
	return srcIP, dstIP, srcPort, dstPort, seq, isSyn
}

// CraftTCPPacketIPv4 compiles raw IPv4 and TCP header buffers, computes checksums, and returns a unified packet slice.
func CraftTCPPacketIPv4(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte, ttl uint32) []byte {
	// IP header (20 bytes)
	ip := make([]byte, 20)
	ip[0] = 0x45 // Version 4, IHL 5
	ip[1] = 0x00 // TOS
	totalLen := 20 + 20 + len(payload)
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))

	nBig, _ := rand.Int(rand.Reader, big.NewInt(65535))
	binary.BigEndian.PutUint16(ip[4:6], uint16(nBig.Int64()))
	ip[6] = 0x40 // Flags: Don't Fragment (DF)
	ip[7] = 0x00
	ip[8] = uint8(ttl)
	ip[9] = 6 // Protocol: TCP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())

	// IP Checksum
	binary.BigEndian.PutUint16(ip[10:12], internetChecksum(ip))

	// TCP Header (20 bytes)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 0x50 // Data offset: 5 (20 bytes)
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 64240) // Window size

	// TCP Checksum pseudo-header calculation
	pseudo := make([]byte, 12+20+len(payload))
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[8] = 0
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(20+len(payload)))
	copy(pseudo[12:32], tcp)
	copy(pseudo[32:], payload)

	binary.BigEndian.PutUint16(tcp[16:18], internetChecksum(pseudo))

	// Assemble final packet
	packet := append(ip, tcp...)
	packet = append(packet, payload...)
	return packet
}

// CraftTCPPacketIPv6 compiles raw IPv6 and TCP header buffers, computes checksums, and returns a unified packet slice.
func CraftTCPPacketIPv6(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte, hopLimit uint32) []byte {
	// IPv6 Header (40 bytes)
	ip := make([]byte, 40)
	ip[0] = 0x60 // Version 6
	// Payload length (TCP header 20 bytes + payload)
	binary.BigEndian.PutUint16(ip[4:6], uint16(20+len(payload)))
	ip[6] = 6 // Next Header: TCP
	ip[7] = uint8(hopLimit)
	copy(ip[8:24], srcIP.To16())
	copy(ip[24:40], dstIP.To16())

	// TCP Header (20 bytes)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 0x50 // Data offset: 5 (20 bytes)
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 64240) // Window size

	// TCP Checksum pseudo-header calculation for IPv6
	pseudo := make([]byte, 40+20+len(payload))
	copy(pseudo[0:16], srcIP.To16())
	copy(pseudo[16:32], dstIP.To16())
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(20+len(payload)))
	pseudo[39] = 6 // Next Header: TCP
	copy(pseudo[40:60], tcp)
	copy(pseudo[60:], payload)

	binary.BigEndian.PutUint16(tcp[16:18], internetChecksum(pseudo))

	// Assemble final packet
	packet := append(ip, tcp...)
	packet = append(packet, payload...)
	return packet
}

// CraftTCPPacket compiles raw IP and TCP header buffers, computes checksums, and returns a unified packet slice.
func CraftTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte, ttl uint32) []byte {
	if srcIP.To4() != nil && dstIP.To4() != nil {
		return CraftTCPPacketIPv4(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, payload, ttl)
	}
	return CraftTCPPacketIPv6(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, payload, ttl)
}

// rawBypassConn implements net.Conn for the GFW Raw Handshake Bypass (paqet mechanics)
type rawBypassConn struct {
	localIP      net.IP
	remoteIP     net.IP
	localPort    uint16
	remotePort   uint16
	seq          uint32
	ack          uint32
	readChan     chan []byte
	closed       chan struct{}
	closeOnce    sync.Once
	readDeadline time.Time
	readBuf      []byte
}

func (c *rawBypassConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: c.localIP, Port: int(c.localPort)}
}

func (c *rawBypassConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: c.remoteIP, Port: int(c.remotePort)}
}

func (c *rawBypassConn) SetDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *rawBypassConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *rawBypassConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *rawBypassConn) Write(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, fmt.Errorf("connection closed")
	default:
	}

	// Craft and inject PSH-ACK packet (flags = 0x18)
	err := InjectWindowsDivertPacket(c.localIP, c.remoteIP, c.localPort, c.remotePort, 64, 0x18, c.seq, c.ack, b)
	if err != nil {
		return 0, err
	}

	// Update seq number
	c.seq = (c.seq + uint32(len(b))) & 0xFFFFFFFF
	return len(b), nil
}

func (c *rawBypassConn) Read(b []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	var timeoutChan <-chan time.Time
	if !c.readDeadline.IsZero() {
		duration := time.Until(c.readDeadline)
		if duration <= 0 {
			return 0, context.DeadlineExceeded
		}
		timeoutChan = time.After(duration)
	}

	select {
	case <-c.closed:
		return 0, fmt.Errorf("connection closed")
	case payload := <-c.readChan:
		n := copy(b, payload)
		if n < len(payload) {
			c.readBuf = payload[n:]
		}
		return n, nil
	case <-timeoutChan:
		return 0, context.DeadlineExceeded
	}
}

func (c *rawBypassConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		_ = RemoveRstDropRule(c.remoteIP.String())
	})
	return nil
}

func getLocalIPForDst(dst net.IP) (net.IP, error) {
	conn, err := net.Dial("udp", dst.String()+":80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP, nil
}

func findFreeLocalPort() (uint16, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port), nil
}

// DialRawBypass connects to the remote host using GFW Raw Handshake Bypass (paqet)
func DialRawBypass(ctx context.Context, host string, port uint16) (net.Conn, error) {
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("failed to resolve host %s: %w", host, err)
	}
	remoteIP := ips[0].To4()
	if remoteIP == nil {
		return nil, fmt.Errorf("IPv6 raw bypass connection not supported yet")
	}

	localIP, err := getLocalIPForDst(remoteIP)
	if err != nil {
		return nil, fmt.Errorf("failed to determine local interface IP: %w", err)
	}

	localPort, err := findFreeLocalPort()
	if err != nil {
		return nil, fmt.Errorf("failed to allocate local port: %w", err)
	}

	var seqVal uint32
	nBig, randErr := rand.Int(rand.Reader, big.NewInt(4294967295))
	if randErr == nil {
		seqVal = uint32(nBig.Uint64())
	} else {
		seqVal = 1000
	}

	conn := &rawBypassConn{
		localIP:    localIP,
		remoteIP:   remoteIP,
		localPort:  localPort,
		remotePort: port,
		seq:        seqVal,
		ack:        0,
		readChan:   make(chan []byte, 100),
		closed:     make(chan struct{}),
	}

	// Install the RST drop rule first; raw-bypass cannot function safely if the
	// host TCP stack is still allowed to emit reset packets.
	if err := InstallRstDropRule(remoteIP.String()); err != nil {
		return nil, fmt.Errorf("install raw-bypass RST rule: %w", err)
	}

	// Acquire the platform sniffer before returning a connection.
	if err := StartBypassSniffer(conn); err != nil {
		_ = RemoveRstDropRule(remoteIP.String())
		return nil, fmt.Errorf("start raw-bypass sniffer: %w", err)
	}

	return conn, nil
}
