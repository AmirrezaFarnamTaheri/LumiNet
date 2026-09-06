package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"net"
	"strings"
	"sync"
)

// Magic identifier byte for raw packet framing ('P' = 0x50).
const (
	RawPacketMagic   byte = 0x50
	RawPacketVersion byte = 0x01

	MsgPing byte = 0x01
	MsgPong byte = 0x02
	MsgTCPF byte = 0x03
	MsgTCP  byte = 0x04
	MsgUDP  byte = 0x05

	HeaderLen    = 5 // MAGIC, VERSION, TYPE, LENGTH(2)
	MaxHostLen   = 253
	MaxTCPFCount = 64
	MaxBodyLen   = 4096
	MaxPort      = 0xFFFF
)

const (
	bFIN uint16 = 1 << 0
	bSYN uint16 = 1 << 1
	bRST uint16 = 1 << 2
	bPSH uint16 = 1 << 3
	bACK uint16 = 1 << 4
	bURG uint16 = 1 << 5
	bECE uint16 = 1 << 6
	bCWR uint16 = 1 << 7
	bNS  uint16 = 1 << 8
)

// RawTCPFlags represents TCP header control flags for crafted evasion bursts.
type RawTCPFlags struct {
	FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS bool
}

// Encode converts the TCP flags struct into a 16-bit wire bitfield.
func (f RawTCPFlags) Encode() uint16 {
	var v uint16
	if f.FIN {
		v |= bFIN
	}
	if f.SYN {
		v |= bSYN
	}
	if f.RST {
		v |= bRST
	}
	if f.PSH {
		v |= bPSH
	}
	if f.ACK {
		v |= bACK
	}
	if f.URG {
		v |= bURG
	}
	if f.ECE {
		v |= bECE
	}
	if f.CWR {
		v |= bCWR
	}
	if f.NS {
		v |= bNS
	}
	return v
}

// DecodeRawTCPFlags converts a 16-bit wire bitfield into a RawTCPFlags struct.
func DecodeRawTCPFlags(v uint16) RawTCPFlags {
	return RawTCPFlags{
		FIN: (v & bFIN) != 0,
		SYN: (v & bSYN) != 0,
		RST: (v & bRST) != 0,
		PSH: (v & bPSH) != 0,
		ACK: (v & bACK) != 0,
		URG: (v & bURG) != 0,
		ECE: (v & bECE) != 0,
		CWR: (v & bCWR) != 0,
		NS:  (v & bNS) != 0,
	}
}

// ParseRawTCPFlags parses combinations such as "PA", "SA", "FA", "FSRPAUECN".
func ParseRawTCPFlags(s string) (RawTCPFlags, error) {
	var f RawTCPFlags
	for _, ch := range s {
		switch ch {
		case 'F', 'f':
			f.FIN = true
		case 'S', 's':
			f.SYN = true
		case 'R', 'r':
			f.RST = true
		case 'P', 'p':
			f.PSH = true
		case 'A', 'a':
			f.ACK = true
		case 'U', 'u':
			f.URG = true
		case 'E', 'e':
			f.ECE = true
		case 'C', 'c':
			f.CWR = true
		case 'N', 'n':
			f.NS = true
		default:
			return f, fmt.Errorf("invalid TCP flag character: '%c'", ch)
		}
	}
	return f, nil
}

// String returns the canonical flag string.
func (f RawTCPFlags) String() string {
	var sb strings.Builder
	if f.FIN {
		sb.WriteRune('F')
	}
	if f.SYN {
		sb.WriteRune('S')
	}
	if f.RST {
		sb.WriteRune('R')
	}
	if f.PSH {
		sb.WriteRune('P')
	}
	if f.ACK {
		sb.WriteRune('A')
	}
	if f.URG {
		sb.WriteRune('U')
	}
	if f.ECE {
		sb.WriteRune('E')
	}
	if f.CWR {
		sb.WriteRune('C')
	}
	if f.NS {
		sb.WriteRune('N')
	}
	return sb.String()
}

// TargetEndpoint specifies an address target.
type TargetEndpoint struct {
	Host string
	Port int
}

// RawPacketMessage represents a wire-level raw packet protocol message.
type RawPacketMessage struct {
	Type   byte
	Target *TargetEndpoint
	Flags  []RawTCPFlags
}

// Encode serializes the message into wire binary format.
func (m *RawPacketMessage) Encode() ([]byte, error) {
	body := make([]byte, 0, 64)

	switch m.Type {
	case MsgPing, MsgPong:
		// No body

	case MsgTCP, MsgUDP:
		if m.Target == nil {
			return nil, errors.New("raw_packet: target endpoint required")
		}
		hostBytes := []byte(m.Target.Host)
		if len(hostBytes) > MaxHostLen {
			return nil, fmt.Errorf("raw_packet: host length %d exceeds max %d", len(hostBytes), MaxHostLen)
		}
		if m.Target.Port < 0 || m.Target.Port > MaxPort {
			return nil, fmt.Errorf("raw_packet: port %d out of range", m.Target.Port)
		}
		body = append(body, byte(len(hostBytes)))
		body = append(body, hostBytes...)
		body = binary.BigEndian.AppendUint16(body, uint16(m.Target.Port))

	case MsgTCPF:
		if len(m.Flags) > MaxTCPFCount {
			return nil, fmt.Errorf("raw_packet: flags count %d exceeds max %d", len(m.Flags), MaxTCPFCount)
		}
		body = append(body, byte(len(m.Flags)))
		for _, f := range m.Flags {
			body = binary.BigEndian.AppendUint16(body, f.Encode())
		}

	default:
		return nil, fmt.Errorf("raw_packet: unknown message type 0x%02x", m.Type)
	}

	if len(body) > MaxBodyLen {
		return nil, fmt.Errorf("raw_packet: body length %d exceeds max %d", len(body), MaxBodyLen)
	}

	out := make([]byte, 0, HeaderLen+len(body))
	out = append(out, RawPacketMagic, RawPacketVersion, m.Type)
	out = binary.BigEndian.AppendUint16(out, uint16(len(body)))
	out = append(out, body...)
	return out, nil
}

// DecodeRawPacketMessage decodes a single message from an io.Reader.
func DecodeRawPacketMessage(r io.Reader) (*RawPacketMessage, error) {
	hdr := make([]byte, HeaderLen)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != RawPacketMagic {
		return nil, fmt.Errorf("raw_packet: bad magic byte 0x%02x (want 0x%02x)", hdr[0], RawPacketMagic)
	}
	if hdr[1] != RawPacketVersion {
		return nil, fmt.Errorf("raw_packet: unsupported version 0x%02x (want 0x%02x)", hdr[1], RawPacketVersion)
	}

	msgType := hdr[2]
	bodyLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if bodyLen > MaxBodyLen {
		return nil, fmt.Errorf("raw_packet: body length %d exceeds max %d", bodyLen, MaxBodyLen)
	}

	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}

	msg := &RawPacketMessage{Type: msgType}
	switch msgType {
	case MsgPing, MsgPong:
		return msg, nil

	case MsgTCP, MsgUDP:
		if len(body) < 3 {
			return nil, errors.New("raw_packet: truncated address body")
		}
		hl := int(body[0])
		if hl > MaxHostLen || 1+hl+2 != len(body) {
			return nil, fmt.Errorf("raw_packet: invalid host length %d", hl)
		}
		host := string(body[1 : 1+hl])
		port := int(binary.BigEndian.Uint16(body[1+hl:]))
		msg.Target = &TargetEndpoint{Host: host, Port: port}
		return msg, nil

	case MsgTCPF:
		if len(body) < 1 {
			return nil, errors.New("raw_packet: truncated tcpf body")
		}
		c := int(body[0])
		if c > MaxTCPFCount || 1+c*2 != len(body) {
			return nil, fmt.Errorf("raw_packet: invalid tcpf count %d", c)
		}
		msg.Flags = make([]RawTCPFlags, c)
		for i := 0; i < c; i++ {
			msg.Flags[i] = DecodeRawTCPFlags(binary.BigEndian.Uint16(body[1+i*2:]))
		}
		return msg, nil

	default:
		return nil, fmt.Errorf("raw_packet: unknown message type 0x%02x", msgType)
	}
}

// DecodeRawPacketBytes decodes a message from a byte slice. Returns message and total bytes consumed.
func DecodeRawPacketBytes(buf []byte) (*RawPacketMessage, int, error) {
	if len(buf) < HeaderLen {
		return nil, 0, errors.New("raw_packet: buffer too short")
	}
	if buf[0] != RawPacketMagic {
		return nil, 0, fmt.Errorf("raw_packet: bad magic byte 0x%02x", buf[0])
	}
	if buf[1] != RawPacketVersion {
		return nil, 0, fmt.Errorf("raw_packet: unsupported version 0x%02x", buf[1])
	}

	msgType := buf[2]
	bodyLen := int(binary.BigEndian.Uint16(buf[3:5]))
	totalLen := HeaderLen + bodyLen
	if len(buf) < totalLen {
		return nil, 0, errors.New("raw_packet: buffer too short for complete frame")
	}

	body := buf[HeaderLen:totalLen]
	msg := &RawPacketMessage{Type: msgType}

	switch msgType {
	case MsgPing, MsgPong:
		return msg, totalLen, nil

	case MsgTCP, MsgUDP:
		if len(body) < 3 {
			return nil, 0, errors.New("raw_packet: truncated address body")
		}
		hl := int(body[0])
		if hl > MaxHostLen || 1+hl+2 != len(body) {
			return nil, 0, fmt.Errorf("raw_packet: invalid host length %d", hl)
		}
		host := string(body[1 : 1+hl])
		port := int(binary.BigEndian.Uint16(body[1+hl:]))
		msg.Target = &TargetEndpoint{Host: host, Port: port}
		return msg, totalLen, nil

	case MsgTCPF:
		if len(body) < 1 {
			return nil, 0, errors.New("raw_packet: truncated tcpf body")
		}
		c := int(body[0])
		if c > MaxTCPFCount || 1+c*2 != len(body) {
			return nil, 0, fmt.Errorf("raw_packet: invalid tcpf count %d", c)
		}
		msg.Flags = make([]RawTCPFlags, c)
		for i := 0; i < c; i++ {
			msg.Flags[i] = DecodeRawTCPFlags(binary.BigEndian.Uint16(body[1+i*2:]))
		}
		return msg, totalLen, nil

	default:
		return nil, 0, fmt.Errorf("raw_packet: unknown message type 0x%02x", msgType)
	}
}

// Internet Checksum calculation (RFC 1071).
func ComputeTCPChecksum(srcIP, dstIP net.IP, tcpHdrAndPayload []byte) uint16 {
	var sum uint32

	ip4 := srcIP.To4()
	dst4 := dstIP.To4()
	if ip4 != nil && dst4 != nil {
		// IPv4 pseudo-header
		sum += uint32(binary.BigEndian.Uint16(ip4[0:2]))
		sum += uint32(binary.BigEndian.Uint16(ip4[2:4]))
		sum += uint32(binary.BigEndian.Uint16(dst4[0:2]))
		sum += uint32(binary.BigEndian.Uint16(dst4[2:4]))
		sum += 6 // Protocol 6 (TCP)
		sum += uint32(len(tcpHdrAndPayload))
	} else {
		// IPv6 pseudo-header
		ip16 := srcIP.To16()
		dst16 := dstIP.To16()
		for i := 0; i < 16; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(ip16[i : i+2]))
		}
		for i := 0; i < 16; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(dst16[i : i+2]))
		}
		sum += uint32(len(tcpHdrAndPayload))
		sum += 6 // NextHeader = TCP
	}

	// Payload / TCP header bytes
	i := 0
	for i+1 < len(tcpHdrAndPayload) {
		sum += uint32(binary.BigEndian.Uint16(tcpHdrAndPayload[i : i+2]))
		i += 2
	}
	if i < len(tcpHdrAndPayload) {
		sum += uint32(tcpHdrAndPayload[i]) << 8
	}

	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// HashIPAddr creates a 64-bit peer hash from IP and port.
func HashIPAddr(ip net.IP, port uint16) uint64 {
	ip4 := ip.To4()
	if ip4 != nil {
		return (uint64(binary.BigEndian.Uint32(ip4)) << 16) | uint64(port)
	}
	ip16 := ip.To16()
	h1 := binary.BigEndian.Uint64(ip16[0:8])
	h2 := binary.BigEndian.Uint64(ip16[8:16])
	return (h1 ^ h2) ^ (uint64(port) << 48)
}

var seed = maphash.MakeSeed()
var hasherPool = sync.Pool{
	New: func() any {
		h := new(maphash.Hash)
		h.SetSeed(seed)
		return h
	},
}

// HashAddrPair hashes a local address and target address pair symmetrically.
func HashAddrPair(localAddr, targetAddr string) uint64 {
	h := hasherPool.Get().(*maphash.Hash)
	defer hasherPool.Put(h)

	h.Reset()
	h.WriteString(localAddr)
	h.WriteByte(0)
	h.WriteString(targetAddr)
	return h.Sum64()
}

// KCPTransportProfile defines transport tuning parameters.
type KCPTransportProfile struct {
	Mode         string
	NoDelay      int
	Interval     int
	Resend       int
	NoCongestion int
	WDelay       bool
	AckNoDelay   bool
	MTU          int
	Sndwnd       int
	Rcvwnd       int
	DSCP         int
}

// NewKCPTransportProfile returns the profile corresponding to preset mode.
func NewKCPTransportProfile(mode string) *KCPTransportProfile {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "fast":
		return &KCPTransportProfile{
			Mode:         "fast",
			NoDelay:      0,
			Interval:     30,
			Resend:       2,
			NoCongestion: 1,
			WDelay:       true,
			AckNoDelay:   false,
			MTU:          1350,
			Sndwnd:       128,
			Rcvwnd:       512,
			DSCP:         46,
		}
	case "fast2":
		return &KCPTransportProfile{
			Mode:         "fast2",
			NoDelay:      1,
			Interval:     20,
			Resend:       2,
			NoCongestion: 1,
			WDelay:       false,
			AckNoDelay:   true,
			MTU:          1350,
			Sndwnd:       128,
			Rcvwnd:       512,
			DSCP:         46,
		}
	case "fast3":
		return &KCPTransportProfile{
			Mode:         "fast3",
			NoDelay:      1,
			Interval:     10,
			Resend:       2,
			NoCongestion: 1,
			WDelay:       false,
			AckNoDelay:   true,
			MTU:          1350,
			Sndwnd:       128,
			Rcvwnd:       512,
			DSCP:         46,
		}
	default: // "normal"
		return &KCPTransportProfile{
			Mode:         "normal",
			NoDelay:      0,
			Interval:     40,
			Resend:       2,
			NoCongestion: 1,
			WDelay:       true,
			AckNoDelay:   false,
			MTU:          1350,
			Sndwnd:       128,
			Rcvwnd:       512,
			DSCP:         46,
		}
	}
}
