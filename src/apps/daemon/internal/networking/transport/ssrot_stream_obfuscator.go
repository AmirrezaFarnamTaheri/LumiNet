package transport

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

type SsrotObfsType int

const (
	SsrotObfsPlain SsrotObfsType = iota
	SsrotObfsHttpSimple
	SsrotObfsTls12TicketAuth
)

type SsrotProtocolType int

const (
	SsrotProtocolOrigin SsrotProtocolType = iota
	SsrotProtocolAuthSha1V4
	SsrotProtocolAuthChainA
)

type SsrotConfig struct {
	Password  string
	Protocol  SsrotProtocolType
	Obfs      SsrotObfsType
	ObfsParam string
}

type SsrotStreamObfuscator struct {
	config    SsrotConfig
	sendID    uint32
	recvID    uint32
	secretKey []byte
}

func NewSsrotStreamObfuscator(config SsrotConfig) *SsrotStreamObfuscator {
	h := md5.Sum([]byte(config.Password))
	return &SsrotStreamObfuscator{
		config:    config,
		sendID:    1,
		recvID:    1,
		secretKey: h[:],
	}
}

func (s *SsrotStreamObfuscator) ClientEncodeHandshake(targetHost string, targetPort uint16, payload []byte) []byte {
	var raw []byte
	hostBytes := []byte(targetHost)

	// [atyp = 3][len][host][port_be][payload]
	raw = append(raw, 3, byte(len(hostBytes)))
	raw = append(raw, hostBytes...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, targetPort)
	raw = append(raw, portBuf...)
	raw = append(raw, payload...)

	protoWrapped := s.wrapProtocol(raw)
	return s.wrapObfs(protoWrapped)
}

func (s *SsrotStreamObfuscator) ServerDecodeHandshake(data []byte) (string, uint16, []byte, error) {
	unwrappedObfs, err := s.unwrapObfs(data)
	if err != nil {
		return "", 0, nil, err
	}

	unwrappedProto, err := s.unwrapProtocol(unwrappedObfs)
	if err != nil {
		return "", 0, nil, err
	}

	if len(unwrappedProto) < 4 {
		return "", 0, nil, errors.New("handshake data too short")
	}

	atyp := unwrappedProto[0]
	if atyp != 3 {
		return "", 0, nil, fmt.Errorf("unsupported atyp: %d", atyp)
	}

	hostLen := int(unwrappedProto[1])
	if len(unwrappedProto) < 2+hostLen+2 {
		return "", 0, nil, errors.New("incomplete host/port in handshake")
	}

	host := string(unwrappedProto[2 : 2+hostLen])
	port := binary.BigEndian.Uint16(unwrappedProto[2+hostLen : 4+hostLen])
	payload := unwrappedProto[4+hostLen:]

	return host, port, payload, nil
}

func (s *SsrotStreamObfuscator) EncodeChunk(data []byte) []byte {
	s.sendID++
	chunk := make([]byte, 2+4+len(data))
	binary.BigEndian.PutUint16(chunk[0:2], uint16(len(data)))
	binary.BigEndian.PutUint32(chunk[2:6], s.sendID)

	for i, b := range data {
		k := s.secretKey[i%len(s.secretKey)]
		chunk[6+i] = b ^ k
	}

	mac := hmac.New(sha256.New, s.secretKey)
	mac.Write(chunk)
	tag := mac.Sum(nil)
	chunk = append(chunk, tag[:4]...)

	return chunk
}

func (s *SsrotStreamObfuscator) DecodeChunk(data []byte) ([]byte, error) {
	if len(data) < 10 {
		return nil, errors.New("chunk too small")
	}

	length := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 6+length+4 {
		return nil, errors.New("incomplete chunk data")
	}

	s.recvID = binary.BigEndian.Uint32(data[2:6])

	mac := hmac.New(sha256.New, s.secretKey)
	mac.Write(data[:6+length])
	tag := mac.Sum(nil)
	if !hmac.Equal(tag[:4], data[6+length:6+length+4]) {
		return nil, errors.New("invalid chunk HMAC tag")
	}

	unmasked := make([]byte, length)
	for i, b := range data[6 : 6+length] {
		k := s.secretKey[i%len(s.secretKey)]
		unmasked[i] = b ^ k
	}

	return unmasked, nil
}

func (s *SsrotStreamObfuscator) wrapProtocol(data []byte) []byte {
	switch s.config.Protocol {
	case SsrotProtocolOrigin:
		return data
	default:
		out := []byte("SSR\x01")
		mac := hmac.New(sha1.New, s.secretKey)
		mac.Write(data)
		tag := mac.Sum(nil)
		out = append(out, tag[:4]...)
		out = append(out, data...)
		return out
	}
}

func (s *SsrotStreamObfuscator) unwrapProtocol(data []byte) ([]byte, error) {
	switch s.config.Protocol {
	case SsrotProtocolOrigin:
		return data, nil
	default:
		if len(data) < 8 || !bytes.HasPrefix(data, []byte("SSR")) {
			return nil, errors.New("invalid protocol header")
		}
		payload := data[8:]
		mac := hmac.New(sha1.New, s.secretKey)
		mac.Write(payload)
		tag := mac.Sum(nil)
		if !hmac.Equal(tag[:4], data[4:8]) {
			return nil, errors.New("protocol HMAC verification failed")
		}
		return payload, nil
	}
}

func (s *SsrotStreamObfuscator) wrapObfs(data []byte) []byte {
	switch s.config.Obfs {
	case SsrotObfsPlain:
		return data
	case SsrotObfsHttpSimple:
		host := s.config.ObfsParam
		if host == "" {
			host = "cloudflare.com"
		}
		header := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nContent-Length: %d\r\n\r\n", host, len(data))
		return append([]byte(header), data...)
	case SsrotObfsTls12TicketAuth:
		out := []byte{0x16, 0x03, 0x03}
		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(len(data)))
		out = append(out, lenBuf...)
		out = append(out, data...)
		return out
	default:
		return data
	}
}

func (s *SsrotStreamObfuscator) unwrapObfs(data []byte) ([]byte, error) {
	switch s.config.Obfs {
	case SsrotObfsPlain:
		return data, nil
	case SsrotObfsHttpSimple:
		delim := []byte("\r\n\r\n")
		idx := bytes.Index(data, delim)
		if idx == -1 {
			return nil, errors.New("invalid HTTP simple framing")
		}
		return data[idx+4:], nil
	case SsrotObfsTls12TicketAuth:
		if len(data) < 5 || data[0] != 0x16 {
			return nil, errors.New("invalid TLS ticket auth framing")
		}
		length := int(binary.BigEndian.Uint16(data[3:5]))
		if len(data) < 5+length {
			return nil, errors.New("incomplete TLS record payload")
		}
		return data[5 : 5+length], nil
	default:
		return data, nil
	}
}
