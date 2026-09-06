// Package system provides platform and system orchestration routines for LumiNet.
//
// SAFECOOKIE authentication handshake (control-spec §4.3) and ownership
// control (§4.5.1 TAKEOWNERSHIP / SETOWNERSHIP). Lets LumiNet talk to a
// Tor control port without ever putting the cookie secret on the wire.
//
// SAFECOOKIE flow:
//   1. Read 32-byte server cookie from `<datadir>/control_auth_cookie`.
//   2. Generate 32 random client nonce.
//   3. Send `AUTHCHALLENGE SAFECOOKIE <client_nonce_hex>`
//   4. Reply contains: server_nonce (32B), server_hash (HMAC-SHA256(key=cookie,
//      "Tor safe cookie authentication controller-to-server hash"|client_nonce|server_nonce))
//   5. Verify server_hash == HMAC(cookie, "Tor safe cookie authentication
//      controller-to-server hash"|client_nonce|server_nonce)
//   6. Send `AUTHENTICATE <client_hash_hex>` where
//      client_hash = HMAC(cookie, "Tor safe cookie authentication server-to-controller hash"|client_nonce|server_nonce)

package system

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/maybeknott/luminet/internal/foundation/boundedio"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	cookieLen                 = 32
	nonceLen                  = 32
	ctrToSrvHashPrefix        = "Tor safe cookie authentication controller-to-server hash"
	srvToCtrlHashPrefix       = "Tor safe cookie authentication server-to-controller hash"
	maxTorControlLineBytes    = 64 << 10
	maxTorControlCommandBytes = 16 << 10
	maxTorControlReplyBytes   = 1 << 20
	defaultTorCommandTimeout  = 10 * time.Second
)

// TorController owns a TCP connection to a Tor control port and performs
// SAFECOOKIE authentication against a known cookie file path. It is safe
// for concurrent use by multiple goroutines: each command takes a mutex.
type TorController struct {
	mu             sync.Mutex
	controlAddr    string
	cookiePath     string
	conn           net.Conn
	reader         *bufio.Reader
	commandTimeout time.Duration
}

// NewTorController builds a controller for `controlAddr` (host:port) and the
// cookie file Tor created in its data directory.
func NewTorController(controlAddr, cookiePath string) *TorController {
	return &TorController{
		controlAddr: controlAddr,
		cookiePath:  cookiePath,
	}
}

// Connect dials the control port and performs SAFECOOKIE auth.
func (c *TorController) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return errors.New("tor_controller: already connected")
	}
	conn, err := net.DialTimeout("tcp", c.controlAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("tor_controller: dial: %w", err)
	}
	c.conn = conn
	c.reader = bufio.NewReader(conn)
	if err := c.safeCookieAuthLocked(); err != nil {
		_ = conn.Close()
		c.conn = nil
		c.reader = nil
		return err
	}
	return nil
}

func (c *TorController) readLineLocked() (string, error) {
	if c.reader == nil {
		return "", errors.New("tor_controller: no control reader")
	}
	line, err := boundedio.ReadLine(c.reader, maxTorControlLineBytes)
	if errors.Is(err, boundedio.ErrLineTooLong) {
		if c.conn != nil {
			_ = c.conn.Close()
		}
		c.conn = nil
		c.reader = nil
		return "", fmt.Errorf("tor_controller: oversized control line: %w", err)
	}
	return line, err
}

// SendRawCommand sends exactly one control command and returns one complete
// non-event reply. Commands containing control characters are rejected before
// any bytes are written. Reply framing follows Tor's status/separator grammar:
// continuation (`250-`), data (`250+` ... `.`), and final (`250 `) elements
// are consumed as one bounded message. Standalone `650` asynchronous events
// that arrive before the command reply are consumed and ignored.
func (c *TorController) SendRawCommand(cmd string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sendCommandLocked(cmd)
}

func (c *TorController) sendCommandLocked(cmd string) (string, error) {
	if c.conn == nil || c.reader == nil {
		return "", errors.New("tor_controller: not connected")
	}
	if err := validateTorControlCommand(cmd); err != nil {
		return "", err
	}

	timeout := c.commandTimeout
	if timeout <= 0 {
		timeout = defaultTorCommandTimeout
	}
	conn := c.conn
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", fmt.Errorf("tor_controller: set deadline: %w", err)
	}
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	if _, err := fmt.Fprintf(conn, "%s\r\n", cmd); err != nil {
		c.breakConnectionLocked()
		return "", fmt.Errorf("tor_controller: write command: %w", err)
	}

	for {
		status, raw, err := c.readMessageLocked()
		if err != nil {
			c.breakConnectionLocked()
			return "", err
		}
		if status == 650 {
			continue
		}
		if status >= 200 && status < 300 {
			return raw, nil
		}
		if status >= 400 && status < 600 {
			return "", fmt.Errorf("tor_controller: command rejected: %s", strings.TrimSpace(raw))
		}
		return "", fmt.Errorf("tor_controller: unexpected reply status %d: %s", status, strings.TrimSpace(raw))
	}
}

func validateTorControlCommand(cmd string) error {
	if strings.TrimSpace(cmd) == "" {
		return errors.New("tor_controller: empty command")
	}
	if len(cmd) > maxTorControlCommandBytes {
		return fmt.Errorf("tor_controller: command length %d exceeds %d", len(cmd), maxTorControlCommandBytes)
	}
	if strings.ContainsAny(cmd, "\r\n\x00") {
		return errors.New("tor_controller: command contains forbidden control character")
	}
	return nil
}

func (c *TorController) readMessageLocked() (int, string, error) {
	var sb strings.Builder
	total := 0
	status := 0

	appendLine := func(line string) error {
		// Account for the normalized newline kept in the returned raw reply.
		if len(line)+1 > maxTorControlReplyBytes-total {
			return fmt.Errorf("tor_controller: reply exceeds %d bytes", maxTorControlReplyBytes)
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
		total += len(line) + 1
		return nil
	}

	for {
		line, err := c.readLineLocked()
		if err != nil {
			return 0, sb.String(), fmt.Errorf("tor_controller: read reply: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		code, sep, err := parseTorControlStatusLine(line)
		if err != nil {
			return 0, sb.String(), err
		}
		if status == 0 {
			status = code
		} else if code != status {
			return 0, sb.String(), fmt.Errorf("tor_controller: reply status changed from %d to %d", status, code)
		}
		if err := appendLine(line); err != nil {
			return 0, sb.String(), err
		}

		switch sep {
		case ' ':
			return status, sb.String(), nil
		case '-':
			continue
		case '+':
			for {
				data, err := c.readLineLocked()
				if err != nil {
					return 0, sb.String(), fmt.Errorf("tor_controller: read data reply: %w", err)
				}
				data = strings.TrimRight(data, "\r\n")
				if data == "." {
					break
				}
				// Dot-stuffed data lines encode a literal leading dot.
				if strings.HasPrefix(data, "..") {
					data = data[1:]
				}
				if err := appendLine(data); err != nil {
					return 0, sb.String(), err
				}
			}
		default:
			return 0, sb.String(), fmt.Errorf("tor_controller: unsupported reply separator %q", sep)
		}
	}
}

func parseTorControlStatusLine(line string) (int, byte, error) {
	if len(line) < 4 {
		return 0, 0, fmt.Errorf("tor_controller: malformed reply line %q", line)
	}
	if line[0] < '0' || line[0] > '9' || line[1] < '0' || line[1] > '9' || line[2] < '0' || line[2] > '9' {
		return 0, 0, fmt.Errorf("tor_controller: malformed reply status %q", line)
	}
	sep := line[3]
	if sep != ' ' && sep != '-' && sep != '+' {
		return 0, 0, fmt.Errorf("tor_controller: malformed reply separator %q", sep)
	}
	status, err := strconv.Atoi(line[:3])
	if err != nil {
		return 0, 0, fmt.Errorf("tor_controller: parse reply status: %w", err)
	}
	return status, sep, nil
}

func (c *TorController) breakConnectionLocked() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.conn = nil
	c.reader = nil
}

// SignalNewNym requests a fresh circuit so future SOCKS5 streams exit
// through a different guard/relay.
func (c *TorController) SignalNewNym() error {
	_, err := c.SendRawCommand("SIGNAL NEWNYM")
	return err
}

// BootstrapProgress queries Tor's client bootstrap phase and returns PROGRESS
// in the inclusive range 0..100. Missing or malformed progress is an error so
// callers cannot mistake an unknown state for a ready daemon.
func (c *TorController) BootstrapProgress() (int, error) {
	reply, err := c.SendRawCommand("GETINFO status/bootstrap-phase")
	if err != nil {
		return 0, err
	}
	for _, tok := range strings.Fields(reply) {
		if !strings.HasPrefix(tok, "PROGRESS=") {
			continue
		}
		v, err := strconv.Atoi(strings.Trim(strings.TrimPrefix(tok, "PROGRESS="), `"`))
		if err != nil || v < 0 || v > 100 {
			return 0, fmt.Errorf("tor_controller: invalid bootstrap progress %q", tok)
		}
		return v, nil
	}
	return 0, errors.New("tor_controller: bootstrap reply missing PROGRESS")
}

// TakeOwnership binds Tor's lifecycle to this controller connection.
func (c *TorController) TakeOwnership(owner string) error {
	if owner == "" || strings.ContainsAny(owner, " \t\r\n\x00") {
		return errors.New("tor_controller: invalid ownership label")
	}
	if _, err := c.SendRawCommand("SETOWNERSHIP " + owner); err != nil {
		return err
	}
	_, err := c.SendRawCommand("TAKEOWNERSHIP")
	return err
}

// Close drops the control connection. If `TAKEOWNERSHIP` was issued
// earlier, Tor also stops itself as a result.
func (c *TorController) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
		c.reader = nil
	}
}

// safeCookieAuthLocked performs the full SAFECOOKIE handshake. Assumes
// the mutex is held and `c.conn` is non-nil.
func (c *TorController) safeCookieAuthLocked() error {
	cookie, err := c.readCookieLocked()
	if err != nil {
		return err
	}

	clientNonce, err := randNonce()
	if err != nil {
		return fmt.Errorf("tor_controller: nonce: %w", err)
	}

	authChallenge, err := c.sendCommandLocked("AUTHCHALLENGE SAFECOOKIE " + hex.EncodeToString(clientNonce))
	if err != nil {
		return err
	}

	serverNonce, serverHash, err := parseAuthChallengeReply(authChallenge)
	if err != nil {
		return err
	}

	// Verify server_hash = HMAC(cookie, ctrToSrvHashPrefix | clientNonce | serverNonce)
	wantServerHash := safeCookieHmac(cookie, []byte(ctrToSrvHashPrefix), clientNonce, serverNonce)
	if !hmac.Equal(serverHash, wantServerHash) {
		return errors.New("tor_controller: server hash mismatch (cookie tampered?)")
	}

	// client_hash = HMAC(cookie, srvToCtrlHashPrefix | clientNonce | serverNonce)
	clientHash := safeCookieHmac(cookie, []byte(srvToCtrlHashPrefix), clientNonce, serverNonce)
	if _, err := c.sendCommandLocked("AUTHENTICATE " + hex.EncodeToString(clientHash)); err != nil {
		return fmt.Errorf("tor_controller: AUTHENTICATE: %w", err)
	}
	return nil
}

func (c *TorController) readCookieLocked() ([]byte, error) {
	if c.cookiePath == "" {
		return nil, errors.New("tor_controller: no cookie path set")
	}
	b, err := readFileBytes(c.cookiePath)
	if err != nil {
		return nil, fmt.Errorf("tor_controller: read cookie: %w", err)
	}
	if len(b) != cookieLen {
		return nil, fmt.Errorf("tor_controller: cookie length %d, want %d", len(b), cookieLen)
	}
	return b, nil
}

// parseAuthChallengeReply parses a complete AUTHCHALLENGE reply.
func parseAuthChallengeReply(raw string) (serverNonce, serverHash []byte, err error) {
	lines := ParseReply(raw)
	if len(lines) == 0 || lines[0].Status != 250 || !strings.HasPrefix(lines[0].Text, "AUTHCHALLENGE") {
		return nil, nil, fmt.Errorf("tor_controller: bad AUTHCHALLENGE reply: %s", strings.TrimSpace(raw))
	}
	line := lines[0].Text
	serverNonce, err = extractHex(line, "SERVERNONCE=", nonceLen)
	if err != nil {
		return nil, nil, err
	}
	serverHash, err = extractHex(line, "SERVERHASH=", sha256.Size)
	if err != nil {
		return nil, nil, err
	}
	return serverNonce, serverHash, nil
}

func extractHex(line, prefix string, wantBytes int) ([]byte, error) {
	idx := strings.Index(line, prefix)
	if idx < 0 {
		return nil, fmt.Errorf("tor_controller: missing %s in %q", prefix, line)
	}
	rest := line[idx+len(prefix):]
	if end := strings.IndexByte(rest, ' '); end >= 0 {
		rest = rest[:end]
	}
	b, err := hex.DecodeString(rest)
	if err != nil {
		return nil, fmt.Errorf("tor_controller: parse %s: %w", prefix, err)
	}
	if len(b) != wantBytes {
		return nil, fmt.Errorf("tor_controller: %s length %d, want %d", prefix, len(b), wantBytes)
	}
	return b, nil
}

func safeCookieHmac(cookie, prefix, clientNonce, serverNonce []byte) []byte {
	mac := hmac.New(sha256.New, cookie)
	mac.Write(prefix)
	mac.Write(clientNonce)
	mac.Write(serverNonce)
	return mac.Sum(nil)
}

func randNonce() ([]byte, error) {
	b := make([]byte, nonceLen)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// readFileBytes is a small wrapper kept here so tor_process.go can DI
// against the same surface (testability via the FS hook in tests).
func readFileBytes(path string) ([]byte, error) {
	// ponytail: real os.ReadFile suffices; indirection makes future in-memory
	// FS fixtures plug in without touching every call site. Inline now — swap
	// when tests need it.
	return os.ReadFile(path)
}

// ReplyLine is one parsed line of a Tor control-port reply. `Multi` is true
// for `250-` continuation lines, false for the final `250 ` terminator.
type ReplyLine struct {
	Status int
	Text   string
	Multi  bool
	Data   bool
}

// ParseReply splits a raw multi-line reply into ReplyLine records.
// Lines without a 3-digit status prefix are returned with Status=0.
func ParseReply(raw string) []ReplyLine {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(raw, "\n")
	out := make([]ReplyLine, 0, len(lines))
	for _, ln := range lines {
		if ln == "" {
			continue
		}
		rl := ReplyLine{Text: ln}
		if len(ln) >= 4 && (ln[3] == '-' || ln[3] == '+') {
			rl.Multi = true
			rl.Data = ln[3] == '+'
			if status, err := strconv.Atoi(ln[0:3]); err == nil {
				rl.Status = status
			}
			rl.Text = ln[4:]
		} else if len(ln) >= 3 {
			if status, err := strconv.Atoi(ln[0:3]); err == nil {
				rl.Status = status
			}
			if len(ln) >= 4 && ln[3] == ' ' {
				rl.Text = ln[4:]
			}
		}
		out = append(out, rl)
	}
	return out
}

// ParseKeywords parses a `key=value key2="quoted value"` token stream as
// emitted by Tor control-port GETINFO replies (control-spec §4.1.1).
// Returns map[lowercase-key]value. Empty/whitespace-only input returns an
// empty map with nil error. Unquoted tokens without `=` are an error.
// Quoted values may contain spaces and escaped quotes via backslash.
func ParseKeywords(line string) (map[string]string, error) {
	out := make(map[string]string)
	i := 0
	n := len(line)
	for i < n {
		for i < n && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= n {
			break
		}
		keyStart := i
		for i < n && line[i] != '=' && line[i] != ' ' && line[i] != '\t' {
			i++
		}
		key := line[keyStart:i]
		if key == "" {
			return nil, fmt.Errorf("tor_controller: empty keyword at offset %d", keyStart)
		}
		if i >= n || line[i] != '=' {
			return nil, fmt.Errorf("tor_controller: keyword %q missing '='", key)
		}
		i++ // consume '='
		var value strings.Builder
		if i < n && line[i] == '"' {
			i++ // consume opening quote
			for i < n && line[i] != '"' {
				if line[i] == '\\' && i+1 < n {
					value.WriteByte(line[i+1])
					i += 2
					continue
				}
				value.WriteByte(line[i])
				i++
			}
			if i < n {
				i++ // consume closing quote
			}
		} else {
			for i < n && line[i] != ' ' && line[i] != '\t' {
				value.WriteByte(line[i])
				i++
			}
		}
		out[strings.ToLower(key)] = value.String()
	}
	return out, nil
}
