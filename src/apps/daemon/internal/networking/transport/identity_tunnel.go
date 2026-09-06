package transport

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

var IdentityTunnelMagic = [4]byte{'P', 'A', 'N', 'G'}

type IdentityTunnelHeader struct {
	Version      uint8
	TargetPort   uint16
	AuthToken    [32]byte
	TargetDomain string
}

func EncodeIdentityTunnelHeader(w io.Writer, targetPort uint16, token [32]byte, domain string) error {
	if len(domain) > 255 {
		return errors.New("domain exceeds 255 bytes")
	}
	if _, err := w.Write(IdentityTunnelMagic[:]); err != nil {
		return err
	}
	headerBuf := make([]byte, 1+2+32+1)
	headerBuf[0] = 1 // version
	binary.BigEndian.PutUint16(headerBuf[1:3], targetPort)
	copy(headerBuf[3:35], token[:])
	headerBuf[35] = byte(len(domain))
	if _, err := w.Write(headerBuf); err != nil {
		return err
	}
	if len(domain) > 0 {
		if _, err := w.Write([]byte(domain)); err != nil {
			return err
		}
	}
	return nil
}

func DecodeIdentityTunnelHeader(r io.Reader) (*IdentityTunnelHeader, error) {
	var magic [4]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, err
	}
	if magic != IdentityTunnelMagic {
		return nil, errors.New("invalid identity tunnel magic")
	}
	buf := make([]byte, 36)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	ver := buf[0]
	if ver != 1 {
		return nil, errors.New("unsupported tunnel version")
	}
	port := binary.BigEndian.Uint16(buf[1:3])
	var tok [32]byte
	copy(tok[:], buf[3:35])
	dLen := int(buf[35])
	dBuf := make([]byte, dLen)
	if _, err := io.ReadFull(r, dBuf); err != nil {
		return nil, err
	}
	return &IdentityTunnelHeader{
		Version:      ver,
		TargetPort:   port,
		AuthToken:    tok,
		TargetDomain: string(dBuf),
	}, nil
}

func VerifyIdentityToken(headerTok [32]byte, secret []byte, subject string) bool {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(subject))
	expected := mac.Sum(nil)
	return hmac.Equal(headerTok[:], expected)
}
