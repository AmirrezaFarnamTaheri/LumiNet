package proxy

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

// ClientHKDFInfo and ServerHKDFInfo are the standard context infos for Brook HKDF derivation.
var ClientHKDFInfo = []byte("brook")
var ServerHKDFInfo = []byte("brook")

// NextNonce increments the first 8 bytes of the 12-byte nonce as a Little-Endian uint64.
func NextNonce(b []byte) {
	if len(b) < 8 {
		return
	}
	i := binary.LittleEndian.Uint64(b[:8])
	i += 1
	binary.LittleEndian.PutUint64(b[:8], i)
}

// BrookConn implements net.Conn for the custom Brook transport protocol.
type BrookConn struct {
	net.Conn
	password []byte
	cn       []byte // client nonce
	sn       []byte // server nonce
	ca       cipher.AEAD
	sa       cipher.AEAD
	readBuf  []byte
	writeBuf []byte
	leftover []byte
}

// DialBrook establishes a Brook proxy connection to a remote server.
func DialBrook(ctx context.Context, network string, serverAddr string, password []byte, dstAddr string) (net.Conn, error) {
	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial raw brook connection: %w", err)
	}

	// 1. Generate client nonce
	cn := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, cn); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("failed to generate client nonce: %w", err)
	}

	// 2. Derive client key and GCM cipher
	ck := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, password, cn, ClientHKDFInfo), ck); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("failed to derive client key: %w", err)
	}
	cb, err := aes.NewCipher(ck)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("failed to initialize client AES: %w", err)
	}
	ca, err := cipher.NewGCM(cb)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("failed to initialize client GCM: %w", err)
	}

	// 3. Write client nonce directly
	if _, err := rawConn.Write(cn); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("failed to write client nonce: %w", err)
	}

	bc := &BrookConn{
		Conn:     rawConn,
		password: password,
		cn:       cn,
		ca:       ca,
		readBuf:  make([]byte, 65536),
		writeBuf: make([]byte, 65536),
	}

	// 4. Send the first fragment: Timestamp + DST Address
	dstBytes, err := encodeAddress(dstAddr)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("failed to encode destination address: %w", err)
	}

	ts := uint32(time.Now().Unix())
	isUDP := strings.HasPrefix(strings.ToLower(network), "udp")
	if isUDP {
		if ts%2 == 0 {
			ts++
		}
	} else {
		if ts%2 != 0 {
			ts++
		}
	}
	tsBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tsBytes, ts)

	firstFragment := append(tsBytes, dstBytes...)
	if err := bc.WriteFragment(firstFragment); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("failed to send first fragment: %w", err)
	}

	// 5. Read server nonce
	sn := make([]byte, 12)
	if _, err := io.ReadFull(rawConn, sn); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("failed to read server nonce: %w", err)
	}
	bc.sn = sn

	// 6. Derive server key and GCM cipher
	sk := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, password, sn, ServerHKDFInfo), sk); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("failed to derive server key: %w", err)
	}
	sb, err := aes.NewCipher(sk)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("failed to initialize server AES: %w", err)
	}
	sa, err := cipher.NewGCM(sb)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("failed to initialize server GCM: %w", err)
	}
	bc.sa = sa

	return bc, nil
}

// Read decrypts and returns incoming data from the server.
func (c *BrookConn) Read(b []byte) (int, error) {
	if len(c.leftover) > 0 {
		n := copy(b, c.leftover)
		c.leftover = c.leftover[n:]
		return n, nil
	}

	// 1. Read encrypted length: 2 bytes length + 16 bytes GCM tag
	encLen := make([]byte, 2+16)
	if _, err := io.ReadFull(c.Conn, encLen); err != nil {
		return 0, err
	}

	// Decrypt length
	decLen := make([]byte, 2)
	if _, err := c.sa.Open(decLen[:0], c.sn, encLen, nil); err != nil {
		return 0, fmt.Errorf("failed to decrypt fragment length: %w", err)
	}
	NextNonce(c.sn)

	l := int(binary.BigEndian.Uint16(decLen))
	if l > len(c.readBuf)-16 {
		return 0, errors.New("fragment length exceeds buffer capacity")
	}

	// 2. Read encrypted fragment: l bytes payload + 16 bytes GCM tag
	encPayload := make([]byte, l+16)
	if _, err := io.ReadFull(c.Conn, encPayload); err != nil {
		return 0, err
	}

	// Decrypt fragment
	decPayload := make([]byte, l)
	if _, err := c.sa.Open(decPayload[:0], c.sn, encPayload, nil); err != nil {
		return 0, fmt.Errorf("failed to decrypt fragment payload: %w", err)
	}
	NextNonce(c.sn)

	n := copy(b, decPayload)
	if n < len(decPayload) {
		c.leftover = append(c.leftover, decPayload[n:]...)
	}
	return n, nil
}

// Write encrypts and writes outgoing data to the server.
func (c *BrookConn) Write(b []byte) (int, error) {
	total := len(b)
	written := 0

	for written < total {
		chunkSize := total - written
		if chunkSize > 2048 {
			chunkSize = 2048
		}

		err := c.WriteFragment(b[written : written+chunkSize])
		if err != nil {
			return written, err
		}
		written += chunkSize
	}

	return total, nil
}

// WriteFragment encrypts and writes a single fragment payload to the server.
func (c *BrookConn) WriteFragment(payload []byte) error {
	l := len(payload)
	// Write buffer framing: 2 bytes length + 16 bytes tag + l bytes payload + 16 bytes tag
	buf := make([]byte, 2+16+l+16)

	binary.BigEndian.PutUint16(buf[:2], uint16(l))

	// Encrypt length using current Client Nonce
	c.ca.Seal(buf[:0], c.cn, buf[:2], nil)
	NextNonce(c.cn)

	// Encrypt payload using rotated Client Nonce
	c.ca.Seal(buf[2+16:2+16], c.cn, payload, nil)
	NextNonce(c.cn)

	_, err := c.Conn.Write(buf)
	return err
}

func encodeAddress(addr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		portStr = "0"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}

	var buf []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = make([]byte, 1+4+2)
			buf[0] = 0x01 // IPv4
			copy(buf[1:5], ip4)
			binary.BigEndian.PutUint16(buf[5:7], uint16(port))
		} else {
			buf = make([]byte, 1+16+2)
			buf[0] = 0x04 // IPv6
			copy(buf[1:17], ip)
			binary.BigEndian.PutUint16(buf[17:19], uint16(port))
		}
	} else {
		hostLen := len(host)
		if hostLen > 255 {
			return nil, errors.New("domain name too long")
		}
		buf = make([]byte, 1+1+hostLen+2)
		buf[0] = 0x03 // Domain
		buf[1] = byte(hostLen)
		copy(buf[2:2+hostLen], host)
		binary.BigEndian.PutUint16(buf[2+hostLen:4+hostLen], uint16(port))
	}
	return buf, nil
}

func decodeAddress(r io.Reader) (string, error) {
	atyp := make([]byte, 1)
	if _, err := io.ReadFull(r, atyp); err != nil {
		return "", err
	}

	var host string
	var port uint16

	switch atyp[0] {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return "", err
		}
		domainLen := int(lenBuf[0])
		domainBytes := make([]byte, domainLen)
		if _, err := io.ReadFull(r, domainBytes); err != nil {
			return "", err
		}
		host = string(domainBytes)
	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	default:
		return "", fmt.Errorf("unsupported atyp: %d", atyp[0])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return "", err
	}
	port = binary.BigEndian.Uint16(portBuf)

	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}
