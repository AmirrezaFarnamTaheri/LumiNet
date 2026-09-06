package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxHTTPProxyHeaderBytes = 32 << 10
	maxHTTPProxySessions    = 256
	httpProxyHandshakeTime  = 10 * time.Second
)

var errHTTPProxyHeaderTooLarge = errors.New("HTTP proxy header too large")

type httpSOCKSBridge struct {
	listener  net.Listener
	socksAddr string
	ctx       context.Context
	cancel    context.CancelFunc
	slots     chan struct{}
	wg        sync.WaitGroup
	mu        sync.Mutex
	clients   map[net.Conn]struct{}
	closeOnce sync.Once
}

func startHTTPSOCKSBridge(socksAddr string) (*httpSOCKSBridge, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(socksAddr))
	if err != nil {
		return nil, fmt.Errorf("invalid SOCKS bridge target: %w", err)
	}
	ip := net.ParseIP(host)
	port, err := strconv.Atoi(portText)
	if ip == nil || !ip.IsLoopback() || err != nil || port < 1 || port > 65535 {
		return nil, errors.New("SOCKS bridge target must be a loopback host with a valid port")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for HTTP system-proxy bridge: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	bridge := &httpSOCKSBridge{
		listener: listener, socksAddr: net.JoinHostPort(ip.String(), strconv.Itoa(port)),
		ctx: ctx, cancel: cancel, slots: make(chan struct{}, maxHTTPProxySessions), clients: make(map[net.Conn]struct{}),
	}
	bridge.wg.Add(1)
	go bridge.acceptLoop()
	return bridge, nil
}

func (b *httpSOCKSBridge) Addr() string {
	if b == nil || b.listener == nil {
		return ""
	}
	return b.listener.Addr().String()
}

func (b *httpSOCKSBridge) Close() error {
	if b == nil {
		return nil
	}
	var closeErr error
	b.closeOnce.Do(func() {
		b.cancel()
		closeErr = b.listener.Close()
		b.mu.Lock()
		clients := make([]net.Conn, 0, len(b.clients))
		for conn := range b.clients {
			clients = append(clients, conn)
		}
		b.mu.Unlock()
		for _, conn := range clients {
			_ = conn.Close()
		}
	})
	b.wg.Wait()
	if errors.Is(closeErr, net.ErrClosed) {
		return nil
	}
	return closeErr
}

func (b *httpSOCKSBridge) acceptLoop() {
	defer b.wg.Done()
	for {
		client, err := b.listener.Accept()
		if err != nil {
			if b.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		select {
		case b.slots <- struct{}{}:
		default:
			writeHTTPProxyError(client, http.StatusServiceUnavailable, "proxy session limit reached")
			_ = client.Close()
			continue
		}
		b.mu.Lock()
		b.clients[client] = struct{}{}
		b.mu.Unlock()
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			defer func() { <-b.slots }()
			defer func() {
				b.mu.Lock()
				delete(b.clients, client)
				b.mu.Unlock()
				_ = client.Close()
			}()
			b.handleClient(client)
		}()
	}
}

func (b *httpSOCKSBridge) handleClient(client net.Conn) {
	_ = client.SetReadDeadline(time.Now().Add(httpProxyHandshakeTime))
	header, buffered, err := readHTTPProxyHeader(client)
	if err != nil {
		if errors.Is(err, errHTTPProxyHeaderTooLarge) {
			writeHTTPProxyError(client, http.StatusRequestHeaderFieldsTooLarge, "request headers too large")
		} else {
			writeHTTPProxyError(client, http.StatusBadRequest, "invalid proxy request")
		}
		return
	}
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(header)))
	if err != nil {
		writeHTTPProxyError(client, http.StatusBadRequest, "invalid proxy request")
		return
	}
	defer request.Body.Close()

	isConnect := strings.EqualFold(request.Method, http.MethodConnect)
	authority := request.Host
	defaultPort := 80
	if isConnect {
		defaultPort = 443
	} else if request.URL != nil && request.URL.Host != "" {
		authority = request.URL.Host
		if strings.EqualFold(request.URL.Scheme, "https") {
			defaultPort = 443
		}
	}
	host, port, err := parseHTTPProxyAuthority(authority, defaultPort)
	if err != nil {
		writeHTTPProxyError(client, http.StatusBadRequest, "invalid proxy target")
		return
	}
	upstream, err := dialSOCKS5Target(b.ctx, b.socksAddr, host, port)
	if err != nil {
		writeHTTPProxyError(client, http.StatusBadGateway, "upstream proxy unavailable")
		return
	}
	defer upstream.Close()
	_ = client.SetReadDeadline(time.Time{})

	if isConnect {
		if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\nProxy-Agent: LumiNet\r\n\r\n"); err != nil {
			return
		}
		if len(buffered) > 0 {
			if _, err := upstream.Write(buffered); err != nil {
				return
			}
		}
		relayHTTPProxySession(client, upstream)
		return
	}

	request.Header.Del("Proxy-Authorization")
	request.Header.Del("Proxy-Connection")
	path := "/"
	if request.URL != nil {
		if value := request.URL.RequestURI(); value != "" {
			path = value
		}
	}
	if _, err := fmt.Fprintf(upstream, "%s %s %s\r\n", request.Method, path, request.Proto); err != nil {
		return
	}
	if request.Host != "" {
		if _, err := fmt.Fprintf(upstream, "Host: %s\r\n", request.Host); err != nil {
			return
		}
	}
	if err := request.Header.Write(upstream); err != nil {
		return
	}
	if _, err := io.WriteString(upstream, "\r\n"); err != nil {
		return
	}
	if len(buffered) > 0 {
		if _, err := upstream.Write(buffered); err != nil {
			return
		}
	}
	relayHTTPProxySession(client, upstream)
}

func readHTTPProxyHeader(conn net.Conn) ([]byte, []byte, error) {
	buffer := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		if len(buffer) > maxHTTPProxyHeaderBytes {
			return nil, nil, errHTTPProxyHeaderTooLarge
		}
		if index := bytes.Index(buffer, []byte("\r\n\r\n")); index >= 0 {
			end := index + 4
			return append([]byte(nil), buffer[:end]...), append([]byte(nil), buffer[end:]...), nil
		}
		n, err := conn.Read(tmp)
		if n > 0 {
			buffer = append(buffer, tmp[:n]...)
			if len(buffer) > maxHTTPProxyHeaderBytes {
				return nil, nil, errHTTPProxyHeaderTooLarge
			}
		}
		if err != nil {
			return nil, nil, err
		}
	}
}

func parseHTTPProxyAuthority(authority string, defaultPort int) (string, int, error) {
	authority = strings.TrimSpace(authority)
	if authority == "" || len(authority) > 1024 {
		return "", 0, errors.New("proxy authority is required")
	}
	host, portText, err := net.SplitHostPort(authority)
	if err != nil {
		if strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") {
			host = strings.TrimSuffix(strings.TrimPrefix(authority, "["), "]")
			portText = strconv.Itoa(defaultPort)
		} else if !strings.Contains(authority, ":") {
			host = authority
			portText = strconv.Itoa(defaultPort)
		} else {
			return "", 0, err
		}
	}
	host = strings.TrimSpace(host)
	if host == "" || len(host) > 255 {
		return "", 0, errors.New("proxy target host is invalid")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, errors.New("proxy target port is invalid")
	}
	return host, port, nil
}

func dialSOCKS5Target(ctx context.Context, socksAddr, host string, port int) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, httpProxyHandshakeTime)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", socksAddr)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(httpProxyHandshakeTime))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, err
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil || greeting != [2]byte{0x05, 0x00} {
		if err == nil {
			err = errors.New("SOCKS5 upstream rejected no-auth method")
		}
		return nil, err
	}
	request := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			request = append(request, 0x01)
			request = append(request, ip4...)
		} else {
			request = append(request, 0x04)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("SOCKS5 target hostname too long")
		}
		request = append(request, 0x03, byte(len(host)))
		request = append(request, host...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))
	request = append(request, portBytes[:]...)
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}
	var reply [4]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return nil, err
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 upstream connect rejected with code %d", reply[1])
	}
	switch reply[3] {
	case 0x01:
		_, err = io.CopyN(io.Discard, conn, 4+2)
	case 0x04:
		_, err = io.CopyN(io.Discard, conn, 16+2)
	case 0x03:
		var length [1]byte
		if _, err = io.ReadFull(conn, length[:]); err == nil {
			_, err = io.CopyN(io.Discard, conn, int64(length[0])+2)
		}
	default:
		err = errors.New("SOCKS5 upstream returned unknown address type")
	}
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	ok = true
	return conn, nil
}

func relayHTTPProxySession(client, upstream net.Conn) {
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go copyOne(upstream, client)
	go copyOne(client, upstream)
	<-done
	_ = client.Close()
	_ = upstream.Close()
	<-done
}

func writeHTTPProxyError(conn net.Conn, status int, message string) {
	body := http.StatusText(status)
	if strings.TrimSpace(message) != "" {
		body = message
	}
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\n\r\n%s", status, http.StatusText(status), len(body), body)
}
