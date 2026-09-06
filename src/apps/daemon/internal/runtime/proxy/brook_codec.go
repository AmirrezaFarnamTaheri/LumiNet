package proxy

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

type BrookTargetType byte

const (
	BrookTargetIPv4   BrookTargetType = 1
	BrookTargetDomain BrookTargetType = 2
	BrookTargetIPv6   BrookTargetType = 3
)

type BrookRequest struct {
	TargetType BrookTargetType
	Host       string
	Port       uint16
}

type BrookCodec struct{}

func NewBrookCodec() *BrookCodec {
	return &BrookCodec{}
}

func (c *BrookCodec) EncodeRequest(w io.Writer, req *BrookRequest) error {
	// 8-byte randomized nonce header to thwart static signature DPI
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	if _, err := w.Write(nonce); err != nil {
		return err
	}

	switch req.TargetType {
	case BrookTargetIPv4:
		ip := net.ParseIP(req.Host).To4()
		if ip == nil {
			return errors.New("invalid ipv4 host")
		}
		buf := make([]byte, 1+4+2)
		buf[0] = byte(BrookTargetIPv4)
		copy(buf[1:5], ip)
		binary.BigEndian.PutUint16(buf[5:7], req.Port)
		_, err := w.Write(buf)
		return err

	case BrookTargetDomain:
		dBytes := []byte(req.Host)
		if len(dBytes) > 255 {
			return errors.New("domain too long")
		}
		buf := make([]byte, 1+1+len(dBytes)+2)
		buf[0] = byte(BrookTargetDomain)
		buf[1] = byte(len(dBytes))
		copy(buf[2:2+len(dBytes)], dBytes)
		binary.BigEndian.PutUint16(buf[2+len(dBytes):], req.Port)
		_, err := w.Write(buf)
		return err

	case BrookTargetIPv6:
		ip := net.ParseIP(req.Host).To16()
		if ip == nil {
			return errors.New("invalid ipv6 host")
		}
		buf := make([]byte, 1+16+2)
		buf[0] = byte(BrookTargetIPv6)
		copy(buf[1:17], ip)
		binary.BigEndian.PutUint16(buf[17:19], req.Port)
		_, err := w.Write(buf)
		return err

	default:
		return errors.New("unsupported brook target type")
	}
}

func (c *BrookCodec) DecodeRequest(r io.Reader) (*BrookRequest, error) {
	nonce := make([]byte, 8)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, err
	}

	tType := make([]byte, 1)
	if _, err := io.ReadFull(r, tType); err != nil {
		return nil, err
	}

	switch BrookTargetType(tType[0]) {
	case BrookTargetIPv4:
		buf := make([]byte, 6)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		ip := net.IP(buf[0:4]).String()
		port := binary.BigEndian.Uint16(buf[4:6])
		return &BrookRequest{TargetType: BrookTargetIPv4, Host: ip, Port: port}, nil

	case BrookTargetDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return nil, err
		}
		dLen := int(lenBuf[0])
		domainBuf := make([]byte, dLen+2)
		if _, err := io.ReadFull(r, domainBuf); err != nil {
			return nil, err
		}
		host := string(domainBuf[:dLen])
		port := binary.BigEndian.Uint16(domainBuf[dLen:])
		return &BrookRequest{TargetType: BrookTargetDomain, Host: host, Port: port}, nil

	case BrookTargetIPv6:
		buf := make([]byte, 18)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		ip := net.IP(buf[0:16]).String()
		port := binary.BigEndian.Uint16(buf[16:18])
		return &BrookRequest{TargetType: BrookTargetIPv6, Host: ip, Port: port}, nil

	default:
		return nil, errors.New("unknown brook target type")
	}
}
