package transport

import (
	"encoding/binary"
	"errors"
)

// MasqueCapsuleType identifies HTTP/3 datagram and capsule types (RFC 9297, RFC 9298)
type MasqueCapsuleType uint64

const (
	CapsuleDatagram           MasqueCapsuleType = 0x00
	CapsuleAddressAssign      MasqueCapsuleType = 0x01
	CapsuleAddressRequest     MasqueCapsuleType = 0x02
	CapsuleRouteAdvertisement MasqueCapsuleType = 0x03
)

// MasqueDatagramTunnel frames and unframes RFC 9298 CONNECT-UDP / CONNECT-IP datagram capsules
type MasqueDatagramTunnel struct {
	contextID uint64
}

// NewMasqueDatagramTunnel creates a new MASQUE datagram tunnel codec
func NewMasqueDatagramTunnel(contextID uint64) *MasqueDatagramTunnel {
	return &MasqueDatagramTunnel{
		contextID: contextID,
	}
}

// EncodeDatagramCapsule encapsulates payload into an HTTP/3 DATAGRAM frame with Context ID
func (t *MasqueDatagramTunnel) EncodeDatagramCapsule(payload []byte) []byte {
	// Variable-length integer encoding for context ID
	var ctxBuf [8]byte
	n := binary.PutUvarint(ctxBuf[:], t.contextID)

	var frame []byte
	frame = append(frame, ctxBuf[:n]...)
	frame = append(frame, payload...)
	return frame
}

// DecodeDatagramCapsule decodes a MASQUE datagram, extracting context ID and raw datagram payload
func (t *MasqueDatagramTunnel) DecodeDatagramCapsule(data []byte) (uint64, []byte, error) {
	if len(data) == 0 {
		return 0, nil, errors.New("empty datagram capsule")
	}

	ctxID, n := binary.Uvarint(data)
	if n <= 0 {
		return 0, nil, errors.New("invalid varint context ID")
	}

	payload := data[n:]
	return ctxID, payload, nil
}

// EncodeAddressRequestCapsule builds an ADDRESS_REQUEST capsule
func (t *MasqueDatagramTunnel) EncodeAddressRequestCapsule(requestedIP string) []byte {
	ipBytes := []byte(requestedIP)
	var header [4]byte
	binary.BigEndian.PutUint16(header[0:2], uint16(CapsuleAddressRequest))
	binary.BigEndian.PutUint16(header[2:4], uint16(len(ipBytes)))

	var frame []byte
	frame = append(frame, header[:]...)
	frame = append(frame, ipBytes...)
	return frame
}
