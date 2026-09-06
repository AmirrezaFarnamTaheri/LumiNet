package tlsdecoy

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
)

// Conn4TupleKey uniquely identifies a tracked TCP connection.
type Conn4TupleKey struct {
	SrcIP   [4]byte
	SrcPort uint16
	DstIP   [4]byte
	DstPort uint16
}

// NewConn4TupleKey creates a new 4-tuple key from IP addresses and ports.
func NewConn4TupleKey(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) Conn4TupleKey {
	var sIP, dIP [4]byte
	if v4 := srcIP.To4(); v4 != nil {
		copy(sIP[:], v4)
	}
	if v4 := dstIP.To4(); v4 != nil {
		copy(dIP[:], v4)
	}
	return Conn4TupleKey{
		SrcIP:   sIP,
		SrcPort: srcPort,
		DstIP:   dIP,
		DstPort: dstPort,
	}
}

// Reverse returns the reverse 4-tuple key for matching reply packets.
func (k Conn4TupleKey) Reverse() Conn4TupleKey {
	return Conn4TupleKey{
		SrcIP:   k.DstIP,
		SrcPort: k.DstPort,
		DstIP:   k.SrcIP,
		DstPort: k.SrcPort,
	}
}

// SniSpoofEngineProfile defines the operational profile for the SNI spoof engine.
type SniSpoofEngineProfile struct {
	ConnectIP   string `json:"connect_ip"`
	ConnectPort int    `json:"connect_port"`
	ListenHost  string `json:"listen_host"`
	ListenPort  int    `json:"listen_port"`
	FakeSNI     string `json:"fake_sni"`
	FastMode    bool   `json:"fast_mode"`
}

// Canonical Cloudflare IPv4 CIDR ranges.
var CloudflareCIDRs = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

var parsedCloudflareCIDRs []*net.IPNet

func init() {
	for _, cidr := range CloudflareCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			parsedCloudflareCIDRs = append(parsedCloudflareCIDRs, ipNet)
		}
	}
}

// IsCloudflareIP checks whether the given IPv4 belongs to any canonical Cloudflare CIDR range.
func IsCloudflareIP(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	for _, ipNet := range parsedCloudflareCIDRs {
		if ipNet.Contains(v4) {
			return true
		}
	}
	return false
}

// CleanDomain sanitizes raw domain inputs by stripping protocols, ports, and comments.
func CleanDomain(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "#") {
		return ""
	}

	if idx := strings.Index(s, "://"); idx != -1 {
		s = s[idx+3:]
	}
	if idx := strings.Index(s, "/"); idx != -1 {
		s = s[:idx]
	}
	if idx := strings.Index(s, ":"); idx != -1 {
		s = s[:idx]
	}

	cleaned := strings.ToLower(strings.TrimSpace(s))
	if cleaned == "" || strings.Contains(cleaned, " ") || !strings.Contains(cleaned, ".") {
		return ""
	}
	return cleaned
}

const (
	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagPSH = 0x08
	tcpFlagACK = 0x10
)

const sniSpoofTemplateHex = "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000010000e000c02683208687474702f312e310016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efdaa98693d217001500d5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
const templateSniLen = 6

// BuildFakeClientHello constructs a canonical 517-byte TLS 1.3 ClientHello packet
// with dynamic SNI extension and RFC 7685 padding balancing.
func BuildFakeClientHello(fakeSNI string, random, sessionID, keyShare [32]byte) ([]byte, error) {
	templateBytes, err := hex.DecodeString(sniSpoofTemplateHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode template hex: %w", err)
	}

	sniBytes := []byte(fakeSNI)
	static1 := templateBytes[:11]
	static2 := []byte{0x20}
	static3 := templateBytes[76:120]
	static4 := templateBytes[(127 + templateSniLen):(262 + templateSniLen)]
	static5 := []byte{0x00, 0x15}

	sniExt := make([]byte, 7+len(sniBytes))
	binary.BigEndian.PutUint16(sniExt[0:2], uint16(len(sniBytes)+5))
	binary.BigEndian.PutUint16(sniExt[2:4], uint16(len(sniBytes)+3))
	sniExt[4] = 0x00 // HostName type
	binary.BigEndian.PutUint16(sniExt[5:7], uint16(len(sniBytes)))
	copy(sniExt[7:], sniBytes)

	padLen := 0
	if len(sniBytes) <= 219 {
		padLen = 219 - len(sniBytes)
	}
	padExt := make([]byte, 2+padLen)
	binary.BigEndian.PutUint16(padExt[0:2], uint16(padLen))

	out := make([]byte, 0, 517)
	out = append(out, static1...)
	out = append(out, random[:]...)
	out = append(out, static2...)
	out = append(out, sessionID[:]...)
	out = append(out, static3...)
	out = append(out, sniExt...)
	out = append(out, static4...)
	out = append(out, keyShare[:]...)
	out = append(out, static5...)
	out = append(out, padExt...)

	return out, nil
}

// BuildFakePayloadPacket constructs an out-of-window decoy packet from a captured ACK snapshot.
func BuildFakePayloadPacket(sourcePacket, fakePayload []byte, fakeSeq uint32) ([]byte, error) {
	if len(sourcePacket) < 40 {
		return nil, errors.New("source packet too short for IPv4 TCP")
	}
	if (sourcePacket[0] >> 4) != 4 {
		return nil, errors.New("packet is not IPv4")
	}
	if sourcePacket[9] != 6 {
		return nil, errors.New("packet protocol is not TCP")
	}

	ipHdrLen := int(sourcePacket[0]&0x0F) * 4
	if len(sourcePacket) < ipHdrLen+20 {
		return nil, errors.New("source packet truncated before TCP header")
	}
	tcpHdrLen := int(sourcePacket[ipHdrLen+12]>>4) * 4
	hdrLen := ipHdrLen + tcpHdrLen
	if len(sourcePacket) < hdrLen {
		return nil, errors.New("source packet truncated before header complete")
	}

	totalSize := hdrLen + len(fakePayload)
	if totalSize > 65535 {
		return nil, errors.New("packet exceeds maximum IPv4 MTU (65535)")
	}

	pkt := make([]byte, totalSize)
	copy(pkt[:hdrLen], sourcePacket[:hdrLen])
	copy(pkt[hdrLen:], fakePayload)

	// Update IPv4 Total Length
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalSize))

	// Increment IPv4 Identification
	ident := binary.BigEndian.Uint16(pkt[4:6])
	binary.BigEndian.PutUint16(pkt[4:6], ident+1)

	// Set TCP PSH flag
	pkt[ipHdrLen+13] |= tcpFlagPSH

	// Overwrite TCP sequence number
	binary.BigEndian.PutUint32(pkt[ipHdrLen+4:ipHdrLen+8], fakeSeq)

	// Recompute IPv4 header checksum
	computeIPv4Checksum(pkt[:ipHdrLen])

	// Recompute TCP checksum
	computeTCPChecksum(pkt, ipHdrLen)

	return pkt, nil
}

func computeIPv4Checksum(ipHdr []byte) {
	ipHdr[10] = 0
	ipHdr[11] = 0
	var sum uint32
	for i := 0; i < len(ipHdr)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ipHdr[i : i+2]))
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	cs := ^uint16(sum)
	binary.BigEndian.PutUint16(ipHdr[10:12], cs)
}

func computeTCPChecksum(pkt []byte, ipHdrLen int) {
	pkt[ipHdrLen+16] = 0
	pkt[ipHdrLen+17] = 0

	var sum uint32
	// Pseudo-header
	sum += uint32(binary.BigEndian.Uint16(pkt[12:14])) // Src IP
	sum += uint32(binary.BigEndian.Uint16(pkt[14:16]))
	sum += uint32(binary.BigEndian.Uint16(pkt[16:18])) // Dst IP
	sum += uint32(binary.BigEndian.Uint16(pkt[18:20]))
	sum += 6                                                  // Protocol
	tcpLen := len(pkt) - ipHdrLen
	sum += uint32(tcpLen)

	// TCP segment
	tcpSeg := pkt[ipHdrLen:]
	for i := 0; i < len(tcpSeg)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcpSeg[i : i+2]))
	}
	if len(tcpSeg)%2 != 0 {
		sum += uint32(tcpSeg[len(tcpSeg)-1]) << 8
	}

	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	cs := ^uint16(sum)
	binary.BigEndian.PutUint16(pkt[ipHdrLen+16:ipHdrLen+18], cs)
}

// KillSwitchState represents whether outbound traffic is currently blocked.
type KillSwitchState int

const (
	KillSwitchInactive KillSwitchState = iota
	KillSwitchArmed
	KillSwitchBlocked
)

// KillSwitchCoordinator manages connection guard and emergency firewall rules.
type KillSwitchCoordinator struct {
	Enabled   bool
	ArmedSNI  bool
	ArmedCore bool
	IsBlocked bool
}

// NewKillSwitchCoordinator initializes the coordinator.
func NewKillSwitchCoordinator(enabled bool) *KillSwitchCoordinator {
	return &KillSwitchCoordinator{
		Enabled: enabled,
	}
}

// OnHeartbeat evaluates core health and determines if an emergency block must be raised.
func (k *KillSwitchCoordinator) OnHeartbeat(sniRunning, coreRunning bool) (triggerBlock bool, restoreUnblock bool) {
	if !k.Enabled {
		if k.IsBlocked {
			k.IsBlocked = false
			return false, true
		}
		return false, false
	}

	if !k.ArmedSNI && !k.ArmedCore {
		return false, false
	}

	dropped := (k.ArmedSNI && !sniRunning) || (k.ArmedCore && !coreRunning)
	if dropped && !k.IsBlocked {
		k.IsBlocked = true
		return true, false
	}

	return false, false
}

// Disarm updates armed status and unblocks if all services disarmed.
func (k *KillSwitchCoordinator) Disarm(sni, core bool) (restoreUnblock bool) {
	if sni {
		k.ArmedSNI = false
	}
	if core {
		k.ArmedCore = false
	}
	if (!k.ArmedSNI && !k.ArmedCore) && k.IsBlocked {
		k.IsBlocked = false
		return true
	}
	return false
}

// NetshBlockRuleArgs returns the command-line arguments to block all outbound traffic via Windows firewall.
func NetshBlockRuleArgs(ruleName string) []string {
	return []string{
		"advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%s", ruleName),
		"dir=out", "action=block", "profile=any", "enable=yes",
	}
}

// NetshUnblockRuleArgs returns the command-line arguments to remove the kill-switch rule.
func NetshUnblockRuleArgs(ruleName string) []string {
	return []string{
		"advfirewall", "firewall", "delete", "rule",
		fmt.Sprintf("name=%s", ruleName),
	}
}
