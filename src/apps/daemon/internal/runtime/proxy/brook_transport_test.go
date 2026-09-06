package proxy

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"
)

func TestBrookTransportLifecycle(t *testing.T) {
	password := []byte("secret-brook-password")
	dstAddr := "google.com:443"

	// 1. Listen on local port
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen TCP: %v", err)
	}
	defer l.Close()

	// 2. Start mock Brook Server
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read client nonce
		cn := make([]byte, 12)
		if _, err := io.ReadFull(conn, cn); err != nil {
			t.Errorf("server failed to read client nonce: %v", err)
			return
		}

		// Derive client key & GCM
		ck := make([]byte, 32)
		_, _ = io.ReadFull(hkdf.New(sha256.New, password, cn, ClientHKDFInfo), ck)
		cb, _ := aes.NewCipher(ck)
		ca, _ := cipher.NewGCM(cb)

		// Read first fragment (Timestamp + DST Address)
		// Encrypted Length (2 bytes + 16 bytes tag)
		encLen := make([]byte, 2+16)
		if _, err := io.ReadFull(conn, encLen); err != nil {
			t.Errorf("server failed to read enc length: %v", err)
			return
		}
		decLen := make([]byte, 2)
		if _, err := ca.Open(decLen[:0], cn, encLen, nil); err != nil {
			t.Errorf("server failed to decrypt length: %v", err)
			return
		}
		NextNonce(cn)

		fragLen := int(binary.BigEndian.Uint16(decLen))
		encFrag := make([]byte, fragLen+16)
		if _, err := io.ReadFull(conn, encFrag); err != nil {
			t.Errorf("server failed to read fragment: %v", err)
			return
		}
		decFrag := make([]byte, fragLen)
		if _, err := ca.Open(decFrag[:0], cn, encFrag, nil); err != nil {
			t.Errorf("server failed to decrypt fragment: %v", err)
			return
		}
		NextNonce(cn)

		// Validate timestamp (first 4 bytes of first fragment)
		ts := binary.BigEndian.Uint32(decFrag[:4])
		now := uint32(time.Now().Unix())
		if now-ts > 60 && ts-now > 60 {
			t.Errorf("server detected expired timestamp: %d (now %d)", ts, now)
			return
		}

		// Write server nonce
		sn := make([]byte, 12)
		_, _ = io.ReadFull(rand.Reader, sn)
		if _, err := conn.Write(sn); err != nil {
			return
		}

		// Derive server key & GCM
		sk := make([]byte, 32)
		_, _ = io.ReadFull(hkdf.New(sha256.New, password, sn, ServerHKDFInfo), sk)
		sb, _ := aes.NewCipher(sk)
		sa, _ := cipher.NewGCM(sb)

		// Echo loop
		// Since this is a mock echoing server, we read from client (encrypted via ca, using cn)
		// and write back to client (encrypted via sa, using sn).
		for {
			encLen := make([]byte, 2+16)
			if _, err := io.ReadFull(conn, encLen); err != nil {
				return
			}
			decLen := make([]byte, 2)
			if _, err := ca.Open(decLen[:0], cn, encLen, nil); err != nil {
				return
			}
			NextNonce(cn)

			l := int(binary.BigEndian.Uint16(decLen))
			encFrag := make([]byte, l+16)
			if _, err := io.ReadFull(conn, encFrag); err != nil {
				return
			}
			decFrag := make([]byte, l)
			if _, err := ca.Open(decFrag[:0], cn, encFrag, nil); err != nil {
				return
			}
			NextNonce(cn)

			// Echo back: encrypt with sa using sn
			outBuf := make([]byte, 2+16+l+16)
			binary.BigEndian.PutUint16(outBuf[:2], uint16(l))
			sa.Seal(outBuf[:0], sn, outBuf[:2], nil)
			NextNonce(sn)

			sa.Seal(outBuf[2+16:2+16], sn, decFrag, nil)
			NextNonce(sn)

			if _, err := conn.Write(outBuf); err != nil {
				return
			}
		}
	}()

	// 3. Connect via DialBrook client
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	bc, err := DialBrook(ctx, "tcp", l.Addr().String(), password, dstAddr)
	if err != nil {
		t.Fatalf("failed to DialBrook client: %v", err)
	}
	defer bc.Close()

	// 4. Write data to connection
	testData := []byte("hello, custom brook protocol transport test payload!")
	if _, err := bc.Write(testData); err != nil {
		t.Fatalf("failed to write data: %v", err)
	}

	// 5. Read echoed data
	readBuf := make([]byte, len(testData))
	if _, err := io.ReadFull(bc, readBuf); err != nil {
		t.Fatalf("failed to read echoed data: %v", err)
	}

	if string(readBuf) != string(testData) {
		t.Errorf("expected echoed data %q, got %q", string(testData), string(readBuf))
	}
}
