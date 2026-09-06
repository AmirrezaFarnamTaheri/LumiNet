// Package system provides platform and system orchestration routines for LumiNet.
//
// Whitelist filter for the Tor control port. Accepts TCP control-port
// connections from a local client, reads each command line, checks the
// command verb against a regex whitelist, and either forwards the line
// to the upstream Tor control port or replies `510 Command disallowed`.
// Mirrors onion-grater's verification mode (regex match →passthrough /
// reject), scoped down to LumiNet's own needs.

package system

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/maybeknott/luminet/internal/foundation/boundedio"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// DefaultControlWhitelist lists the complete command shapes LumiNet exposes to
// callers through the control-port proxy. NewControlFilter anchors every entry
// at both ends so a safe prefix cannot authorize trailing arguments.
var DefaultControlWhitelist = []string{
	`GETINFO\s+(version|status/bootstrap-phase|netinfo)`,
	`SIGNAL\s+(NEWNYM|RELOAD|CLEARDNSCACHE)`,
	`SETOWNERSHIP\s+\S+`,
	`TAKEOWNERSHIP`,
	`AUTHCHALLENGE\s+SAFECOOKIE\s+[0-9a-fA-F]+`,
	`AUTHENTICATE\s+[0-9a-fA-F]+`,
	`QUIT`,
}

// ControlFilter is a single-port proxy that enforces a whitelist between
// untrusted local callers and the real Tor control port.
type ControlFilter struct {
	mu           sync.Mutex
	listenAddr   string
	upstreamAddr string
	compiled     []*regexp.Regexp
	listener     net.Listener
	acceptCancel context.CancelFunc
}

// NewControlFilter builds a filter listening on `listenAddr` and proxying
// whitelisted commands to `upstreamAddr` (the real Tor control port).
// If `patterns` is nil, [`DefaultControlWhitelist`] is used.
func NewControlFilter(listenAddr, upstreamAddr string, patterns []string) (*ControlFilter, error) {
	if patterns == nil {
		patterns = DefaultControlWhitelist
	}
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile("(?i)^(?:" + p + ")$")
		if err != nil {
			return nil, fmt.Errorf("control_filter: bad pattern %q: %w", p, err)
		}
		compiled = append(compiled, re)
	}
	return &ControlFilter{
		listenAddr:   listenAddr,
		upstreamAddr: upstreamAddr,
		compiled:     compiled,
	}, nil
}

// Serve starts accepting connections and blocks until `ctx` is cancelled
// or the listener errors. Each connection is handled in its own goroutine.
func (f *ControlFilter) Serve(ctx context.Context) error {
	f.mu.Lock()
	if f.listener != nil {
		f.mu.Unlock()
		return errors.New("control_filter: already serving")
	}
	l, err := net.Listen("tcp", f.listenAddr)
	if err != nil {
		f.mu.Unlock()
		return fmt.Errorf("control_filter: listen: %w", err)
	}
	f.listener = l
	srvCtx, cancel := context.WithCancel(ctx)
	f.acceptCancel = cancel
	f.mu.Unlock()

	defer func() {
		_ = l.Close()
		f.mu.Lock()
		f.listener = nil
		f.acceptCancel = nil
		f.mu.Unlock()
	}()

	go func() {
		<-srvCtx.Done()
		_ = l.Close()
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			if srvCtx.Err() != nil {
				return nil
			}
			return err
		}
		go f.handleConn(srvCtx, conn)
	}
}

// Stop unblocks `Serve` and closes the listener.
func (f *ControlFilter) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.acceptCancel != nil {
		f.acceptCancel()
		f.acceptCancel = nil
	}
	if f.listener != nil {
		_ = f.listener.Close()
	}
}

// handleConn is per-client: opens upstream, reads commands, gates each
// command against the whitelist before forwarding. Commands not matching
// any whitelist entry earn a `510 Command disallowed\r\n` reply that is
// written back to the client without hitting Tor.
func (f *ControlFilter) handleConn(ctx context.Context, client net.Conn) {
	defer client.Close()
	upstream, err := net.DialTimeout("tcp", f.upstreamAddr, 5*time.Second)
	if err != nil {
		fmt.Fprintf(client, "510 Cannot reach upstream\r\n")
		return
	}
	defer upstream.Close()

	clientReader := bufio.NewReader(client)
	// One aggregator goroutine forwards upstream->client.
	go func() {
		_, _ = io.Copy(client, upstream)
		_ = client.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		line, err := boundedio.ReadLine(clientReader, 16<<10)
		if err != nil {
			return
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if !f.allowed(trimmed) {
			fmt.Fprintf(client, "510 Command disallowed\r\n")
			continue
		}
		if _, err := upstream.Write([]byte(line)); err != nil {
			return
		}
	}
}

// allowed returns true when `line` matches any whitelist pattern.
func (f *ControlFilter) allowed(line string) bool {
	for _, re := range f.compiled {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

// Whitelist returns a copy of the compiled whitelist patterns (for tests).
func (f *ControlFilter) Whitelist() []*regexp.Regexp {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*regexp.Regexp, len(f.compiled))
	copy(out, f.compiled)
	return out
}
