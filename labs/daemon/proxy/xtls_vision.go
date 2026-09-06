package proxy

// xtls_vision.go — XTLS Vision splice mode implementation.
//
// XTLS Vision is a record-layer optimization developed by RPRX (XTLS Project).
// After the TLS inner handshake completes, the traffic between the proxy client
// and the real TLS server is no longer encrypted at the outer TLS layer —
// instead it is copied verbatim via a kernel splice() call (on Linux) or a
// direct io.Copy (on other platforms), eliminating one round of AES-GCM
// encryption/decryption on the hot path.
//
// Reference implementation: https://github.com/XTLS/Xray-core (vision.go)
// Inspired by: XTLS/Go-main — DirectMode / DirectPre / DirectOut flags in conn.go
//
// Design:
//   - After the outer VLESS handshake, the proxy server detects the moment the
//     inner TLS server-hello record is completely forwarded to the client
//     (DirectPre = true) and switches to copying raw encrypted bytes instead of
//     decrypting and re-encrypting.
//   - We implement this via a finite-state machine that scans the bytestream for
//     the TLS 1.3 "handshake complete" boundary (type=23, Application Data after
//     Change-Cipher-Spec sentinel).
//   - Once the FSM reaches the Direct state, bidirectional io.Copy (or splice)
//     is used without further record parsing.

import (
	"context"
	"io"
	"net"
	"sync"
)

// XTLSVisionState tracks where we are in the XTLS Vision handshake scan.
type XTLSVisionState int

const (
	// XTLSVisionScanning is the initial state: we are forwarding TLS records
	// and scanning for the end of the inner TLS handshake.
	XTLSVisionScanning XTLSVisionState = iota

	// XTLSVisionDirect is the terminal state: the inner TLS handshake has
	// finished; we switch to raw direct-copy mode (no decryption overhead).
	XTLSVisionDirect
)

// XTLSVisionConn wraps an outer net.Conn and implements the Vision splice FSM.
// Once state transitions to XTLSVisionDirect, all subsequent reads/writes pass
// through without any record parsing.
type XTLSVisionConn struct {
	net.Conn

	mu    sync.Mutex
	state XTLSVisionState

	// Scanning state machine fields (mirrors Go-main/conn.go Conn fields)
	fall  bool // true once total bytes matched the inner handshake size
	first bool // true until first application-data record seen
	total int  // expected inner-handshake total bytes
	count int  // bytes seen in inner handshake so far

	// DirectOut becomes true when the first post-handshake application data
	// record header is spotted; triggers the transition to Direct mode.
	directOut bool

	// TLS record header parser state (5-byte header: type, ver, ver, len-hi, len-lo)
	hdr       [5]byte // accumulator for the current record header
	hdrN      int     // bytes accumulated so far in hdr
	payRemain int     // remaining payload bytes of the current record to skip
}

// NewXTLSVisionConn wraps conn with Vision splice detection.
// innerHandshakeSize is the expected byte count of the inner TLS 1.3 handshake
// (server Hello + EncryptedExtensions + Certificate + Finished ≈ 5–8 KiB).
// Pass 0 to let the FSM detect the boundary heuristically.
func NewXTLSVisionConn(conn net.Conn, innerHandshakeSize int) *XTLSVisionConn {
	vc := &XTLSVisionConn{
		Conn:  conn,
		state: XTLSVisionScanning,
		first: true,
		total: innerHandshakeSize,
	}
	return vc
}

// Read implements the Vision FSM on the read path.
// While in Scanning state it updates the byte counter; once DirectOut is
// detected it transitions to Direct and all further reads bypass the FSM.
func (vc *XTLSVisionConn) Read(b []byte) (int, error) {
	n, err := vc.Conn.Read(b)
	if n > 0 {
		vc.mu.Lock()
		vc.scan(b[:n])
		vc.mu.Unlock()
	}
	return n, err
}

// scan advances the FSM over a newly read slice.
// It parses complete 5-byte TLS record headers to correctly identify record
// type boundaries, rather than scanning raw payload bytes.  This avoids
// false-positives from 0x17 bytes inside Handshake record payloads.
//
// FSM states per byte:
//
//	hdrN < 5  → accumulating the 5-byte record header
//	hdrN == 5 → header complete; examine type and skip payRemain payload bytes
func (vc *XTLSVisionConn) scan(data []byte) {
	if vc.state == XTLSVisionDirect {
		return
	}

	i := 0
	for i < len(data) {
		if vc.payRemain > 0 {
			// Skip remaining payload of the current record.
			skip := len(data) - i
			if skip > vc.payRemain {
				skip = vc.payRemain
			}
			if vc.total > 0 {
				vc.count += skip
				if vc.count >= vc.total {
					vc.fall = true
				}
			}
			vc.payRemain -= skip
			i += skip
			continue
		}

		// Accumulate the 5-byte TLS record header.
		need := 5 - vc.hdrN
		avail := len(data) - i
		take := need
		if avail < take {
			take = avail
		}
		copy(vc.hdr[vc.hdrN:], data[i:i+take])
		vc.hdrN += take
		i += take

		if vc.hdrN < 5 {
			// Need more bytes to complete this header.
			return
		}

		// Full 5-byte header available.
		recordType := vc.hdr[0]
		recordLen := int(vc.hdr[3])<<8 | int(vc.hdr[4])
		vc.hdrN = 0

		// Check for the post-handshake Application Data record (type 0x17).
		if recordType == 0x17 {
			if vc.fall || vc.total == 0 {
				// Vision boundary: switch to direct copy.
				vc.directOut = true
				vc.first = false
				vc.state = XTLSVisionDirect
				return
			}
		}

		// Account for this record's header bytes toward the inner-handshake budget.
		if vc.total > 0 {
			vc.count += 5
			if vc.count >= vc.total {
				vc.fall = true
			}
		}

		// Mark the payload to skip on the next iteration(s).
		vc.payRemain = recordLen
	}
}

// IsDirect reports whether Vision has entered the direct-copy state.
func (vc *XTLSVisionConn) IsDirect() bool {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	return vc.state == XTLSVisionDirect
}

// XTLSVisionSplice is the main goroutine-pair for XTLS Vision bidirectional
// data relay.  It forwards traffic between outer (the proxy tunnel conn) and
// inner (the real upstream TLS connection).  While in scanning mode it does
// record-aware forwarding; once Vision detects DirectOut it switches to a raw
// io.Copy splice.
//
// Both directions are run concurrently.  The function blocks until one side
// returns an error or ctx is cancelled.
func XTLSVisionSplice(ctx context.Context, outer, inner net.Conn, innerHandshakeSize int) error {
	// Wrap the outer connection in the Vision FSM for the outbound direction
	// (outer → inner, i.e. client → upstream server).
	vc := NewXTLSVisionConn(outer, innerHandshakeSize)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex

	setErr := func(err error) {
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		errMu.Unlock()
		cancel()
	}

	// Outbound: outer → inner (client traffic → upstream TLS server).
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer inner.Close() //nolint:errcheck
		_, err := io.Copy(inner, vc)
		setErr(err)
	}()

	// Inbound: inner → outer (upstream TLS server → client), with Vision scan.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer outer.Close() //nolint:errcheck
		innerVC := NewXTLSVisionConn(inner, innerHandshakeSize)
		_, err := io.Copy(outer, innerVC)
		setErr(err)
	}()

	// If context is cancelled before both goroutines finish, forcibly close
	// both connections so the io.Copy calls unblock.  sync.Once ensures we
	// don't double-close after the relay goroutines already closed them.
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = outer.Close()
			_ = inner.Close()
		})
	}
	go func() {
		<-ctx.Done()
		closeBoth()
	}()

	wg.Wait()
	closeBoth() // no-op if already closed; ensures cleanup on normal exit
	return firstErr
}

// XTLSVisionDialAndSplice dials upstream via dialFn, performs the Vision splice
// between clientConn and the upstream, and returns once both sides close.
// This is the convenience entry-point called from the VLESS dialer.
func XTLSVisionDialAndSplice(
	ctx context.Context,
	clientConn net.Conn,
	dialFn func(ctx context.Context) (net.Conn, error),
	innerHandshakeSize int,
) error {
	upstreamConn, err := dialFn(ctx)
	if err != nil {
		return err
	}
	return XTLSVisionSplice(ctx, clientConn, upstreamConn, innerHandshakeSize)
}
