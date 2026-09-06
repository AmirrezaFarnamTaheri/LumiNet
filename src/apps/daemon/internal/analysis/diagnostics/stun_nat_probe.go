package diagnostics

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/netpolicy"
)

const (
	stunBindingRequest       uint16 = 0x0001
	stunBindingSuccess       uint16 = 0x0101
	stunBindingError         uint16 = 0x0111
	stunMagicCookie          uint32 = 0x2112A442
	stunAttrMappedAddress    uint16 = 0x0001
	stunAttrXORMappedAddress uint16 = 0x0020
	stunAttrResponseOrigin   uint16 = 0x802b
	stunAttrOtherAddress     uint16 = 0x802c
	defaultSTUNPort                 = 3478
	defaultSTUNTimeout              = 2 * time.Second
	maxSTUNTimeout                  = 5 * time.Second
	defaultSTUNAttempts             = 2
	maxSTUNAttempts                 = 3
	maxSTUNPacketBytes              = 2048
	maxIgnoredSTUNPackets           = 8
)

// STUNMappingProbeRequest asks for a bounded RFC 5389 mapping observation.
// It intentionally does not promise full NAT cone/filter classification: that
// requires RFC 5780 behavior from the server and more probes than this safe
// diagnostic needs.
type STUNMappingProbeRequest struct {
	Primary   string        `json:"primary"`
	Secondary string        `json:"secondary,omitempty"`
	Timeout   time.Duration `json:"-"`
	Attempts  int           `json:"attempts,omitempty"`
}

// STUNMappingProbeResult reports only behavior directly supported by observed
// STUN replies. MappingBehavior is "endpoint-independent",
// "endpoint-dependent-or-port-dependent", or "unknown".
type STUNMappingProbeResult struct {
	PrimaryServer          string   `json:"primary_server"`
	PrimaryMappedAddress   string   `json:"primary_mapped_address"`
	ResponseOrigin         string   `json:"response_origin,omitempty"`
	OtherAddress           string   `json:"other_address,omitempty"`
	SecondaryServer        string   `json:"secondary_server,omitempty"`
	SecondaryMappedAddress string   `json:"secondary_mapped_address,omitempty"`
	MappingBehavior        string   `json:"mapping_behavior"`
	Attempts               int      `json:"attempts"`
	Evidence               []string `json:"evidence"`
}

type stunBindingObservation struct {
	mapped         *net.UDPAddr
	responseOrigin *net.UDPAddr
	other          *net.UDPAddr
}

// ProbeSTUNMapping sends at most maxSTUNAttempts tiny binding requests per
// destination from one UDP socket. User- and server-provided destinations must
// resolve exclusively to public addresses, preventing the diagnostic from
// becoming an internal-network UDP oracle.
func ProbeSTUNMapping(ctx context.Context, req STUNMappingProbeRequest) (STUNMappingProbeResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultSTUNTimeout
	}
	if timeout > maxSTUNTimeout {
		return STUNMappingProbeResult{}, fmt.Errorf("STUN timeout must be <= %s", maxSTUNTimeout)
	}
	attempts := req.Attempts
	if attempts <= 0 {
		attempts = defaultSTUNAttempts
	}
	if attempts > maxSTUNAttempts {
		return STUNMappingProbeResult{}, fmt.Errorf("STUN attempts must be between 1 and %d", maxSTUNAttempts)
	}

	primary, err := resolvePublicSTUNEndpoint(ctx, req.Primary)
	if err != nil {
		return STUNMappingProbeResult{}, fmt.Errorf("primary STUN endpoint: %w", err)
	}
	network := "udp4"
	if primary.IP.To4() == nil {
		network = "udp6"
	}
	conn, err := net.ListenUDP(network, nil)
	if err != nil {
		return STUNMappingProbeResult{}, fmt.Errorf("open STUN socket: %w", err)
	}
	defer conn.Close()

	primaryObs, usedAttempts, err := transactSTUN(ctx, conn, primary, timeout, attempts)
	if err != nil {
		return STUNMappingProbeResult{}, fmt.Errorf("primary STUN binding: %w", err)
	}
	result := STUNMappingProbeResult{
		PrimaryServer:        primary.String(),
		PrimaryMappedAddress: primaryObs.mapped.String(),
		MappingBehavior:      "unknown",
		Attempts:             usedAttempts,
		Evidence:             []string{"primary binding response returned a mapped address"},
	}
	if primaryObs.responseOrigin != nil {
		result.ResponseOrigin = primaryObs.responseOrigin.String()
	}
	if primaryObs.other != nil {
		result.OtherAddress = primaryObs.other.String()
	}

	var secondary *net.UDPAddr
	if strings.TrimSpace(req.Secondary) != "" {
		secondary, err = resolvePublicSTUNEndpoint(ctx, req.Secondary)
		if err != nil {
			return STUNMappingProbeResult{}, fmt.Errorf("secondary STUN endpoint: %w", err)
		}
	} else if primaryObs.other != nil {
		if !udpAddressIsPublic(primaryObs.other) {
			return STUNMappingProbeResult{}, errors.New("primary STUN server returned non-public OTHER-ADDRESS")
		}
		secondary = primaryObs.other
	}
	if secondary == nil || sameUDPEndpoint(primary, secondary) {
		result.Evidence = append(result.Evidence, "no distinct secondary destination was available; mapping dependence is unknown")
		return result, nil
	}
	if (primary.IP.To4() == nil) != (secondary.IP.To4() == nil) {
		result.Evidence = append(result.Evidence, "secondary destination uses a different IP family; same-socket mapping comparison was skipped")
		return result, nil
	}

	secondaryObs, secondaryAttempts, err := transactSTUN(ctx, conn, secondary, timeout, attempts)
	result.Attempts += secondaryAttempts
	if err != nil {
		result.SecondaryServer = secondary.String()
		result.Evidence = append(result.Evidence, "secondary binding failed; mapping dependence remains unknown")
		return result, nil
	}
	result.SecondaryServer = secondary.String()
	result.SecondaryMappedAddress = secondaryObs.mapped.String()
	if sameUDPEndpoint(primaryObs.mapped, secondaryObs.mapped) {
		result.MappingBehavior = "endpoint-independent"
		result.Evidence = append(result.Evidence, "the same local socket kept the same mapped address across distinct STUN destinations")
	} else {
		result.MappingBehavior = "endpoint-dependent-or-port-dependent"
		result.Evidence = append(result.Evidence, "the mapped address changed across distinct STUN destinations")
	}
	return result, nil
}

func resolvePublicSTUNEndpoint(ctx context.Context, raw string) (*net.UDPAddr, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("endpoint is required")
	}
	host, portText, err := net.SplitHostPort(raw)
	if err != nil {
		if strings.Contains(raw, ":") && net.ParseIP(raw) == nil {
			return nil, fmt.Errorf("invalid host:port %q", raw)
		}
		host = raw
		portText = strconv.Itoa(defaultSTUNPort)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid UDP port %q", portText)
	}

	var addresses []netip.Addr
	if parsed, parseErr := netip.ParseAddr(strings.Trim(host, "[]")); parseErr == nil {
		addresses = []netip.Addr{parsed}
	} else {
		addresses, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolve %q: %w", host, err)
		}
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("resolve %q: no addresses", host)
	}
	for _, address := range addresses {
		if !netpolicy.IsPublicAddress(address) {
			return nil, fmt.Errorf("refused non-public STUN address %s", address)
		}
	}
	selected := addresses[0]
	return &net.UDPAddr{IP: net.IP(selected.AsSlice()), Port: port}, nil
}

func transactSTUN(ctx context.Context, conn *net.UDPConn, target *net.UDPAddr, timeout time.Duration, attempts int) (stunBindingObservation, int, error) {
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		transactionID, request, err := buildSTUNBindingRequest()
		if err != nil {
			return stunBindingObservation{}, attempt - 1, err
		}
		deadline := time.Now().Add(timeout)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		if err := conn.SetDeadline(deadline); err != nil {
			return stunBindingObservation{}, attempt - 1, err
		}
		if _, err := conn.WriteToUDP(request, target); err != nil {
			lastErr = err
			continue
		}
		for ignored := 0; ignored < maxIgnoredSTUNPackets; ignored++ {
			buf := make([]byte, maxSTUNPacketBytes)
			n, source, err := conn.ReadFromUDP(buf)
			if err != nil {
				lastErr = err
				break
			}
			if !sameUDPEndpoint(source, target) {
				continue
			}
			obs, err := parseSTUNBindingResponse(buf[:n], transactionID)
			if err != nil {
				lastErr = err
				continue
			}
			if obs.responseOrigin != nil && !sameUDPEndpoint(obs.responseOrigin, source) {
				lastErr = errors.New("STUN RESPONSE-ORIGIN does not match packet source")
				continue
			}
			return obs, attempt, nil
		}
		if err := ctx.Err(); err != nil {
			return stunBindingObservation{}, attempt, err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no valid STUN response")
	}
	return stunBindingObservation{}, attempts, lastErr
}

func buildSTUNBindingRequest() ([12]byte, []byte, error) {
	var transactionID [12]byte
	if _, err := rand.Read(transactionID[:]); err != nil {
		return transactionID, nil, fmt.Errorf("generate STUN transaction ID: %w", err)
	}
	request := make([]byte, 20)
	binary.BigEndian.PutUint16(request[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(request[2:4], 0)
	binary.BigEndian.PutUint32(request[4:8], stunMagicCookie)
	copy(request[8:20], transactionID[:])
	return transactionID, request, nil
}

func parseSTUNBindingResponse(packet []byte, transactionID [12]byte) (stunBindingObservation, error) {
	if len(packet) < 20 {
		return stunBindingObservation{}, errors.New("STUN response shorter than header")
	}
	messageType := binary.BigEndian.Uint16(packet[0:2])
	if messageType == stunBindingError {
		return stunBindingObservation{}, errors.New("STUN server returned a binding error")
	}
	if messageType != stunBindingSuccess {
		return stunBindingObservation{}, fmt.Errorf("unexpected STUN message type 0x%04x", messageType)
	}
	messageLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if messageLength > len(packet)-20 || messageLength%4 != 0 {
		return stunBindingObservation{}, errors.New("invalid STUN message length")
	}
	if binary.BigEndian.Uint32(packet[4:8]) != stunMagicCookie {
		return stunBindingObservation{}, errors.New("invalid STUN magic cookie")
	}
	if string(packet[8:20]) != string(transactionID[:]) {
		return stunBindingObservation{}, errors.New("STUN transaction ID mismatch")
	}

	var obs stunBindingObservation
	for offset, end := 20, 20+messageLength; offset+4 <= end; {
		attrType := binary.BigEndian.Uint16(packet[offset : offset+2])
		attrLen := int(binary.BigEndian.Uint16(packet[offset+2 : offset+4]))
		valueStart := offset + 4
		valueEnd := valueStart + attrLen
		if valueEnd > end {
			return stunBindingObservation{}, errors.New("truncated STUN attribute")
		}
		value := packet[valueStart:valueEnd]
		var addr *net.UDPAddr
		var err error
		switch attrType {
		case stunAttrXORMappedAddress:
			addr, err = decodeSTUNAddress(value, transactionID, true)
			if err == nil {
				obs.mapped = addr
			}
		case stunAttrMappedAddress:
			if obs.mapped == nil {
				addr, err = decodeSTUNAddress(value, transactionID, false)
				if err == nil {
					obs.mapped = addr
				}
			}
		case stunAttrResponseOrigin:
			addr, err = decodeSTUNAddress(value, transactionID, false)
			if err == nil {
				obs.responseOrigin = addr
			}
		case stunAttrOtherAddress:
			addr, err = decodeSTUNAddress(value, transactionID, false)
			if err == nil {
				obs.other = addr
			}
		}
		if err != nil {
			return stunBindingObservation{}, fmt.Errorf("decode STUN attribute 0x%04x: %w", attrType, err)
		}
		offset = valueStart + ((attrLen + 3) &^ 3)
	}
	if obs.mapped == nil {
		return stunBindingObservation{}, errors.New("STUN response lacks mapped address")
	}
	return obs, nil
}

func decodeSTUNAddress(value []byte, transactionID [12]byte, xor bool) (*net.UDPAddr, error) {
	if len(value) < 4 || value[0] != 0 {
		return nil, errors.New("invalid STUN address attribute")
	}
	family := value[1]
	port := binary.BigEndian.Uint16(value[2:4])
	if xor {
		port ^= uint16(stunMagicCookie >> 16)
	}
	switch family {
	case 0x01:
		if len(value) != 8 {
			return nil, errors.New("invalid STUN IPv4 address length")
		}
		bytes := append([]byte(nil), value[4:8]...)
		if xor {
			cookie := make([]byte, 4)
			binary.BigEndian.PutUint32(cookie, stunMagicCookie)
			for i := range bytes {
				bytes[i] ^= cookie[i]
			}
		}
		return &net.UDPAddr{IP: net.IP(bytes), Port: int(port)}, nil
	case 0x02:
		if len(value) != 20 {
			return nil, errors.New("invalid STUN IPv6 address length")
		}
		bytes := append([]byte(nil), value[4:20]...)
		if xor {
			mask := make([]byte, 16)
			binary.BigEndian.PutUint32(mask[:4], stunMagicCookie)
			copy(mask[4:], transactionID[:])
			for i := range bytes {
				bytes[i] ^= mask[i]
			}
		}
		return &net.UDPAddr{IP: net.IP(bytes), Port: int(port)}, nil
	default:
		return nil, fmt.Errorf("unsupported STUN address family 0x%02x", family)
	}
}

func sameUDPEndpoint(left, right *net.UDPAddr) bool {
	if left == nil || right == nil || left.Port != right.Port {
		return false
	}
	return left.IP.Equal(right.IP)
}

func udpAddressIsPublic(address *net.UDPAddr) bool {
	if address == nil {
		return false
	}
	parsed, ok := netip.AddrFromSlice(address.IP)
	return ok && netpolicy.IsPublicAddress(parsed.Unmap())
}
