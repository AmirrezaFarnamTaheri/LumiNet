package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// RelayNetwork defines the target transport network type.
type RelayNetwork string

const (
	RelayNetworkTCP RelayNetwork = "tcp"
	RelayNetworkUDP RelayNetwork = "udp"
)

// RelayStreamHeader represents destination addressing metadata for an egress relay.
// Directly mirrors lumicore::relay::relay_stream_codec.
type RelayStreamHeader struct {
	Network RelayNetwork
	Host    string
	Port    uint16
}

// EncodeV1 encodes into ASCII delimiter format: <network>@<host>$<port>\r.
func (h *RelayStreamHeader) EncodeV1() []byte {
	return []byte(fmt.Sprintf("%s@%s$%d\r", h.Network, h.Host, h.Port))
}

// DecodeV1 decodes an ASCII delimiter formatted relay header.
// Returns the parsed header and the number of bytes consumed (including '\r').
func DecodeV1(src []byte) (*RelayStreamHeader, int, error) {
	if len(src) == 0 {
		return nil, 0, errors.New("empty buffer")
	}

	crPos := bytes.IndexByte(src, '\r')
	if crPos == -1 {
		return nil, 0, errors.New("missing delimiter \\r")
	}

	slice := src[:crPos]
	atPos := bytes.IndexByte(slice, '@')
	if atPos == -1 {
		return nil, 0, errors.New("missing delimiter @")
	}

	netStr := strings.ToLower(string(slice[:atPos]))
	var network RelayNetwork
	switch netStr {
	case "tcp":
		network = RelayNetworkTCP
	case "udp":
		network = RelayNetworkUDP
	default:
		return nil, 0, fmt.Errorf("invalid relay network: %s", netStr)
	}

	rest := slice[atPos+1:]
	dollarPos := bytes.IndexByte(rest, '$')
	if dollarPos == -1 {
		return nil, 0, errors.New("missing delimiter $")
	}

	host := string(rest[:dollarPos])
	portStr := string(rest[dollarPos+1:])
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid port string: %s", portStr)
	}

	return &RelayStreamHeader{
		Network: network,
		Host:    host,
		Port:    uint16(port64),
	}, crPos + 1, nil
}

// EncodeV2 encodes into compact binary wire format:
// Magic [0x52, 0x32] ('R2') + NetByte (1=TCP, 2=UDP) + Port (uint16 BE) + HostLen (uint8) + HostBytes
func (h *RelayStreamHeader) EncodeV2() []byte {
	hostBytes := []byte(h.Host)
	if len(hostBytes) > 255 {
		hostBytes = hostBytes[:255]
	}

	buf := make([]byte, 6+len(hostBytes))
	buf[0] = 'R'
	buf[1] = '2'
	if h.Network == RelayNetworkTCP {
		buf[2] = 1
	} else {
		buf[2] = 2
	}
	binary.BigEndian.PutUint16(buf[3:5], h.Port)
	buf[5] = byte(len(hostBytes))
	copy(buf[6:], hostBytes)

	return buf
}

// DecodeV2 decodes a compact binary relay header.
func DecodeV2(src []byte) (*RelayStreamHeader, int, error) {
	if len(src) < 6 {
		return nil, 0, errors.New("buffer too short for relay v2 header")
	}

	if src[0] != 'R' || src[1] != '2' {
		return nil, 0, errors.New("invalid relay v2 magic bytes")
	}

	var network RelayNetwork
	switch src[2] {
	case 1:
		network = RelayNetworkTCP
	case 2:
		network = RelayNetworkUDP
	default:
		return nil, 0, fmt.Errorf("unknown network byte: %d", src[2])
	}

	port := binary.BigEndian.Uint16(src[3:5])
	hostLen := int(src[5])
	totalLen := 6 + hostLen

	if len(src) < totalLen {
		return nil, 0, errors.New("buffer truncated for relay v2 host")
	}

	host := string(src[6:totalLen])

	return &RelayStreamHeader{
		Network: network,
		Host:    host,
		Port:    port,
	}, totalLen, nil
}
