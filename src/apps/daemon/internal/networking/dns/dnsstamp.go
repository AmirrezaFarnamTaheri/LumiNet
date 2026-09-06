// Package dns: DNS stamps (sdns://) parsing.
//
// (MIT, (c) Frank Denis <j@pureftpd.org>), absorbing the read/parse path
// (ServerStamp + NewServerStampFromString + per-protocol grammars) into the
// LumiNet DNS subsystem. The write path (String()/stamp builders) is not
// ported; LumiNet only consumes operator feeds.
//
// Grammar summary:
//
//	plain:          id(u8)=0x00 props(le u64) addrLen(1) addr
//	dnscrypt:       id(u8)=0x01 props addrLen(1) addr pkLen(1) pk providerLen(1) provider
//	doh:            id(u8)=0x02 props addrLen(1) addr hashes(vlp,32B each) providerLen(1) provider pathLen(1) path [bootstrap vlp]
//	dot/doq:        id(u8)=0x03/0x04 props addrLen(1) addr hashes(vlp) providerLen(1) provider [bootstrap vlp]
//	odohtarget:     id(u8)=0x05 props providerLen(1) provider pathLen(1) path
//	dnscrypt relay: id(u8)=0x81 addrLen(1) addr
package dns

import (
	"encoding/hex"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	stampDefaultPort    = 443
	stampDefaultDoTPort = 853
	stampDefaultDNSPort = 53
	// StampScheme is the URI scheme prefix of a DNS stamp.
	StampScheme = "sdns://"
)

// ServerInformalProperties is the bitset of informal server properties.
type ServerInformalProperties uint64

const (
	ServerInformalPropertyDNSSEC   = ServerInformalProperties(1) << 0
	ServerInformalPropertyNoLog    = ServerInformalProperties(1) << 1
	ServerInformalPropertyNoFilter = ServerInformalProperties(1) << 2
)

// StampProtoType identifies the protocol encoded by a stamp.
type StampProtoType uint8

const (
	StampProtoTypePlain         StampProtoType = 0x00
	StampProtoTypeDNSCrypt      StampProtoType = 0x01
	StampProtoTypeDoH           StampProtoType = 0x02
	StampProtoTypeTLS           StampProtoType = 0x03
	StampProtoTypeDoQ           StampProtoType = 0x04
	StampProtoTypeODoHTarget    StampProtoType = 0x05
	StampProtoTypeDNSCryptRelay StampProtoType = 0x81
	StampProtoTypeODoHRelay     StampProtoType = 0x85
)

// String implements fmt.Stringer.
func (p StampProtoType) String() string {
	switch p {
	case StampProtoTypePlain:
		return "Plain"
	case StampProtoTypeDNSCrypt:
		return "DNSCrypt"
	case StampProtoTypeDoH:
		return "DoH"
	case StampProtoTypeTLS:
		return "TLS"
	case StampProtoTypeDoQ:
		return "QUIC"
	case StampProtoTypeODoHTarget:
		return "oDoH target"
	case StampProtoTypeDNSCryptRelay:
		return "DNSCrypt relay"
	case StampProtoTypeODoHRelay:
		return "oDoH relay"
	default:
		return "(unknown)"
	}
}

// ServerStamp is the normalised form of one sdns:// stamp.
type ServerStamp struct {
	ServerAddrStr string
	ServerPk      []uint8
	Hashes        [][]uint8
	ProviderName  string
	Path          string
	Props         ServerInformalProperties
	Proto         StampProtoType
	BootstrapIPs  []string
}

// NewDNSCryptServerStampFromLegacy builds a DNSCrypt stamp from the legacy
// (addr, pk, provider) triple; upstream parity for old feed rows.
func NewDNSCryptServerStampFromLegacy(serverAddrStr, serverPkStr, providerName string, props ServerInformalProperties) (ServerStamp, error) {
	if net.ParseIP(serverAddrStr) != nil {
		serverAddrStr = fmt.Sprintf("%s:%d", serverAddrStr, stampDefaultPort)
	}
	serverPk, err := hexDecodeColoned(serverPkStr)
	if err != nil || len(serverPk) != 32 {
		return ServerStamp{}, fmt.Errorf("unsupported public key: [%s]", serverPkStr)
	}
	return ServerStamp{
		ServerAddrStr: serverAddrStr,
		ServerPk:      serverPk,
		ProviderName:  providerName,
		Props:         props,
		Proto:         StampProtoTypeDNSCrypt,
	}, nil
}

// ParseServerStamp decodes one "sdns://" stamp string.
func ParseServerStamp(stampStr string) (ServerStamp, error) {
	if !strings.HasPrefix(stampStr, "sdns:") {
		return ServerStamp{}, errors.New("stamps are expected to start with \"sdns:\"")
	}
	stampStr = stampStr[5:]
	stampStr = strings.TrimPrefix(stampStr, "//")
	bin, err := base64.RawURLEncoding.Strict().DecodeString(stampStr)
	if err != nil {
		return ServerStamp{}, err
	}
	if len(bin) < 1 {
		return ServerStamp{}, errors.New("stamp is too short")
	}
	switch StampProtoType(bin[0]) {
	case StampProtoTypePlain:
		return parsePlainStamp(bin)
	case StampProtoTypeDNSCrypt:
		return parseDNSCryptStamp(bin)
	case StampProtoTypeDoH:
		return parseDoHStamp(bin)
	case StampProtoTypeTLS:
		return parseDoTStamp(bin)
	case StampProtoTypeDoQ:
		return parseDoTStamp(bin) // same grammar as DoT per upstream
	case StampProtoTypeODoHTarget:
		return parseODoHTargetStamp(bin)
	case StampProtoTypeDNSCryptRelay:
		return parseDNSCryptRelayStamp(bin)
	default:
		return ServerStamp{}, fmt.Errorf("unsupported stamp protocol: %v", StampProtoType(bin[0]))
	}
}

// hexDecodeColoned decodes a hex string that may contain ":" separators
// (legacy public-key format), upstream parity.
func hexDecodeColoned(s string) ([]byte, error) {
	return hex.DecodeString(strings.ReplaceAll(s, ":", ""))
}

// ---- batch parser --------------------------------------------------------

// StampParseError records one malformed line in a multi-stamp feed.
type StampParseError struct {
	Line int
	Err  error
}

// ParseServerStampList splits a multi-line operator feed (one stamp per
// line) and parses each recognised entry. Lines that fail to parse are
// skipped with their error recorded, so a partially-malformed feed does
// not abort ingestion - the caller can inspect the []StampParseError to
// surface a partial-success report.
func ParseServerStampList(content string) ([]ServerStamp, []StampParseError) {
	var stamps []ServerStamp
	var errs []StampParseError
	for i, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, StampScheme) {
			continue
		}
		s, err := ParseServerStamp(line)
		if err != nil {
			errs = append(errs, StampParseError{Line: i + 1, Err: err})
			continue
		}
		stamps = append(stamps, s)
	}
	return stamps, errs
}

// ---- per-protocol parsers -------------------------------------------------

// parseVLP reads a sequence of length-prefixed values. The final entry of
// the sequence is flagged by the 0x80 bit of the length byte (upstream
// "variable-length prefix" convention); a 0-length entry is skipped.
func parseVLP(bin []byte, pos int) ([]string, int, error) {
	var out []string
	for {
		if pos >= len(bin) {
			return nil, pos, errors.New("invalid stamp (vlp overrun)")
		}
		vlen := int(bin[pos])
		length := vlen & ^0x80
		pos++
		if pos+length > len(bin) {
			return nil, pos, errors.New("invalid stamp (vlp truncated)")
		}
		if length > 0 {
			out = append(out, string(bin[pos:pos+length]))
		}
		pos += length
		if vlen&0x80 != 0x80 {
			return out, pos, nil
		}
	}
}

func parsePlainStamp(bin []byte) (ServerStamp, error) {
	stamp := ServerStamp{Proto: StampProtoTypePlain}
	if len(bin) < 1+8+1+1 {
		return stamp, errors.New("stamp is too short")
	}
	stamp.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
	pos := 9
	length := int(bin[pos])
	if 1+length > len(bin)-pos {
		return stamp, errors.New("invalid stamp")
	}
	pos++
	stamp.ServerAddrStr = string(bin[pos : pos+length])
	pos += length
	addr, err := normalizeIPPort(stamp.ServerAddrStr, stampDefaultDNSPort)
	if err != nil {
		return stamp, err
	}
	stamp.ServerAddrStr = addr
	if pos != len(bin) {
		return stamp, errors.New("invalid stamp (garbage after end)")
	}
	return stamp, nil
}

func parseDNSCryptStamp(bin []byte) (ServerStamp, error) {
	stamp := ServerStamp{Proto: StampProtoTypeDNSCrypt}
	if len(bin) < 66 {
		return stamp, errors.New("stamp is too short")
	}
	stamp.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
	pos := 9
	length := int(bin[pos])
	if 1+length >= len(bin)-pos {
		return stamp, errors.New("invalid stamp")
	}
	pos++
	stamp.ServerAddrStr = string(bin[pos : pos+length])
	pos += length
	addr, err := normalizeIPPort(stamp.ServerAddrStr, stampDefaultPort)
	if err != nil {
		return stamp, err
	}
	stamp.ServerAddrStr = addr

	length = int(bin[pos])
	if 1+length >= len(bin)-pos {
		return stamp, errors.New("invalid stamp")
	}
	pos++
	stamp.ServerPk = append([]byte(nil), bin[pos:pos+length]...)
	pos += length

	length = int(bin[pos])
	if length >= len(bin)-pos {
		return stamp, errors.New("invalid stamp")
	}
	pos++
	stamp.ProviderName = string(bin[pos : pos+length])
	pos += length

	if pos != len(bin) {
		return stamp, errors.New("invalid stamp (garbage after end)")
	}
	return stamp, nil
}

// parseHashedServerStamp covers the DoH (0x02) and DoT/DoQ (0x03/0x04)
// grammars, which share the hashed-certificate shape. withPath selects the
// DoH variant (trailing path field).
func parseHashedServerStamp(bin []byte, proto StampProtoType, withPath bool) (ServerStamp, error) {
	stamp := ServerStamp{Proto: proto}
	minLen := 13
	if withPath {
		minLen = 15
	}
	if len(bin) < minLen {
		return stamp, errors.New("stamp is too short")
	}
	stamp.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
	pos := 9
	length := int(bin[pos])
	if 1+length >= len(bin)-pos {
		return stamp, errors.New("invalid stamp")
	}
	pos++
	stamp.ServerAddrStr = string(bin[pos : pos+length])
	pos += length

	// Certificate hashes: repeated length-prefixed entries, 0x80 bit marks
	// the last one. Each non-empty hash must be exactly 32 bytes.
	for {
		if pos >= len(bin) {
			return stamp, errors.New("invalid stamp (hash overrun)")
		}
		vlen := int(bin[pos])
		length = vlen & ^0x80
		if 1+length >= len(bin)-pos {
			return stamp, errors.New("invalid stamp")
		}
		pos++
		if length > 0 {
			if length != 32 {
				return stamp, errors.New("invalid stamp (certificate hash must be 32 bytes)")
			}
			stamp.Hashes = append(stamp.Hashes, append([]byte(nil), bin[pos:pos+length]...))
		}
		pos += length
		if vlen&0x80 != 0x80 {
			break
		}
	}

	length = int(bin[pos])
	if length >= len(bin)-pos {
		return stamp, errors.New("invalid stamp")
	}
	pos++
	stamp.ProviderName = string(bin[pos : pos+length])
	pos += length

	if withPath {
		length = int(bin[pos])
		if length >= len(bin)-pos {
			return stamp, errors.New("invalid stamp")
		}
		pos++
		stamp.Path = string(bin[pos : pos+length])
		pos += length
	}

	// Optional bootstrap IPs (VLP format).
	if pos < len(bin) {
		ips, npos, err := parseVLP(bin, pos)
		if err != nil {
			return stamp, err
		}
		stamp.BootstrapIPs = ips
		pos = npos
	}

	if pos != len(bin) {
		return stamp, errors.New("invalid stamp (garbage after end)")
	}
	return stamp, nil
}

func parseDoHStamp(bin []byte) (ServerStamp, error) {
	s, err := parseHashedServerStamp(bin, StampProtoTypeDoH, true)
	if err != nil {
		return s, err
	}
	if err := validateAddrAndHostname(s.ServerAddrStr, s.ProviderName); err != nil {
		return s, err
	}
	return s, nil
}

func parseDoTStamp(bin []byte) (ServerStamp, error) {
	return parseHashedServerStamp(bin, StampProtoType(bin[0]), false)
}

func parseODoHTargetStamp(bin []byte) (ServerStamp, error) {
	stamp := ServerStamp{Proto: StampProtoTypeODoHTarget}
	if len(bin) < 12 {
		return stamp, errors.New("stamp is too short")
	}
	stamp.Props = ServerInformalProperties(binary.LittleEndian.Uint64(bin[1:9]))
	pos := 9
	length := int(bin[pos])
	if 1+length >= len(bin)-pos {
		return stamp, errors.New("invalid stamp")
	}
	pos++
	stamp.ProviderName = string(bin[pos : pos+length])
	pos += length

	length = int(bin[pos])
	if length >= len(bin)-pos {
		return stamp, errors.New("invalid stamp")
	}
	pos++
	stamp.Path = string(bin[pos : pos+length])
	pos += length

	if pos != len(bin) {
		return stamp, errors.New("invalid stamp (garbage after end)")
	}
	if _, err := stripAndValidatePort(stamp.ProviderName); err != nil {
		return stamp, err
	}
	return stamp, nil
}

func parseDNSCryptRelayStamp(bin []byte) (ServerStamp, error) {
	stamp := ServerStamp{Proto: StampProtoTypeDNSCryptRelay}
	if len(bin) < 9 {
		return stamp, errors.New("stamp is too short")
	}
	pos := 1
	length := int(bin[pos])
	if 1+length > len(bin)-pos {
		return stamp, errors.New("invalid stamp")
	}
	pos++
	stamp.ServerAddrStr = string(bin[pos : pos+length])
	pos += length
	addr, err := normalizeIPPort(stamp.ServerAddrStr, stampDefaultPort)
	if err != nil {
		return stamp, err
	}
	stamp.ServerAddrStr = addr
	if pos != len(bin) {
		return stamp, errors.New("invalid stamp (garbage after end)")
	}
	return stamp, nil
}

// ---- validation helpers ----------------------------------------------------

// normalizeIPPort validates an ip:port pair, appending a default port when
// absent (bracket-aware for IPv6). Upstream inline logic, extracted.
func normalizeIPPort(addr string, defaultPort int) (string, error) {
	colIndex := strings.LastIndex(addr, ":")
	bracketIndex := strings.LastIndex(addr, "]")
	if colIndex < bracketIndex {
		colIndex = -1
	}
	if colIndex < 0 {
		return fmt.Sprintf("%s:%d", addr, defaultPort), nil
	}
	if colIndex >= len(addr)-1 {
		return "", errors.New("invalid stamp (empty port)")
	}
	ipOnly := addr[:colIndex]
	if err := validatePortStr(addr[colIndex+1:]); err != nil {
		return "", err
	}
	if net.ParseIP(strings.TrimRight(strings.TrimLeft(ipOnly, "["), "]")) == nil {
		return "", errors.New("invalid stamp (IP address)")
	}
	return addr, nil
}

func validatePortStr(portStr string) error {
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port < 1 {
		return errors.New("invalid stamp (port range)")
	}
	return nil
}

// validateAddrAndHostname: DoH/DoQ require either an IP address (with
// bootstrap implied) or a hostname with at least one dot.
func validateAddrAndHostname(serverAddrStr, providerName string) error {
	if strings.HasPrefix(serverAddrStr, "2") {
		return nil // 2.x addresses are reserved for bootstrap-less configs
	}
	if strings.HasPrefix(serverAddrStr, "1") {
		return nil
	}
	if net.ParseIP(serverAddrStr) != nil {
		return nil
	}
	providerName, err := stripAndValidatePort(providerName)
	if err != nil {
		return err
	}
	if strings.Contains(providerName, ".") {
		return nil
	}
	return errors.New("invalid stamp (hostname)")
}

func stripAndValidatePort(hostPort string) (string, error) {
	colIndex := strings.LastIndex(hostPort, ":")
	if colIndex < 0 {
		return hostPort, nil
	}
	if err := validatePortStr(hostPort[colIndex+1:]); err != nil {
		return "", err
	}
	return hostPort[:colIndex], nil
}
