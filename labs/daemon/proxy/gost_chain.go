// Ported from: gost-master
// Target path: server/internal/proxy/gost_chain.go

package proxy

import (
	"context"
	"fmt"
	"net"
)

// ProxyNode represents a single proxy hop in a chain.
type ProxyNode struct {
	Protocol string // "socks5", "http", "ss"
	Address  string // host:port
	Username string
	Password string
}

// ProxyChain manages multiple hops of outbound proxies.
type ProxyChain struct {
	Nodes []ProxyNode
}

// NewProxyChain creates an empty proxy chain.
func NewProxyChain(nodes ...ProxyNode) *ProxyChain {
	return &ProxyChain{Nodes: nodes}
}

// Dial connects to the target address by establishing sequential tunnels through the chain.
func (c *ProxyChain) Dial(ctx context.Context, network, destAddr string) (net.Conn, error) {
	if len(c.Nodes) == 0 {
		// No proxy hops, dial directly
		var d net.Dialer
		return d.DialContext(ctx, network, destAddr)
	}

	// Dial first hop
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", c.Nodes[0].Address)
	if err != nil {
		return nil, fmt.Errorf("gost_chain: failed to dial first hop %s: %w", c.Nodes[0].Address, err)
	}

	// Establish tunnels sequentially
	for i := 0; i < len(c.Nodes); i++ {
		nextAddr := destAddr
		if i+1 < len(c.Nodes) {
			nextAddr = c.Nodes[i+1].Address
		}

		var errTunnel error
		conn, errTunnel = c.establishTunnel(ctx, conn, c.Nodes[i], nextAddr)
		if errTunnel != nil {
			conn.Close()
			return nil, fmt.Errorf("gost_chain: failed to tunnel hop %d (%s) -> %s: %w", i, c.Nodes[i].Protocol, nextAddr, errTunnel)
		}
	}

	return conn, nil
}

func (c *ProxyChain) establishTunnel(ctx context.Context, conn net.Conn, node ProxyNode, nextAddr string) (net.Conn, error) {
	switch node.Protocol {
	case "socks5":
		return c.handshakeSocks5(conn, node, nextAddr)
	case "http":
		return c.handshakeHTTP(conn, node, nextAddr)
	default:
		// Unknown or raw connection (passthrough)
		return conn, nil
	}
}

func (c *ProxyChain) handshakeSocks5(conn net.Conn, node ProxyNode, nextAddr string) (net.Conn, error) {
	// SOCKS5 greeting
	_, err := conn.Write([]byte{0x05, 0x01, 0x00}) // SOCKS5, 1 auth method, No Auth
	if err != nil {
		return nil, err
	}

	resp := make([]byte, 2)
	_, err = ioReadFull(conn, resp)
	if err != nil {
		return nil, err
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return nil, fmt.Errorf("socks5 greeting failed: %x", resp)
	}

	// SOCKS5 request: Connect cmd
	host, port, err := splitHostPortStr(nextAddr)
	if err != nil {
		return nil, err
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))

	_, err = conn.Write(req)
	if err != nil {
		return nil, err
	}

	// SOCKS5 response
	respHeader := make([]byte, 4)
	_, err = ioReadFull(conn, respHeader)
	if err != nil {
		return nil, err
	}
	if respHeader[1] != 0x00 {
		return nil, fmt.Errorf("socks5 connect failed: status=%d", respHeader[1])
	}

	// Consume address in response
	addrType := respHeader[3]
	var skipLen int
	switch addrType {
	case 0x01: // IPv4
		skipLen = 4 + 2
	case 0x03: // Domain name
		lenByte := make([]byte, 1)
		_, err = ioReadFull(conn, lenByte)
		if err != nil {
			return nil, err
		}
		skipLen = int(lenByte[0]) + 2
	case 0x04: // IPv6
		skipLen = 16 + 2
	}
	skipBuf := make([]byte, skipLen)
	_, _ = ioReadFull(conn, skipBuf)

	return conn, nil
}

func (c *ProxyChain) handshakeHTTP(conn net.Conn, node ProxyNode, nextAddr string) (net.Conn, error) {
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", nextAddr, nextAddr)
	_, err := conn.Write([]byte(req))
	if err != nil {
		return nil, err
	}

	// Read response status
	// Read until "\r\n\r\n"
	buf := make([]byte, 0, 1024)
	temp := make([]byte, 1)
	for {
		_, err = conn.Read(temp)
		if err != nil {
			return nil, err
		}
		buf = append(buf, temp[0])
		if len(buf) >= 4 && string(buf[len(buf)-4:]) == "\r\n\r\n" {
			break
		}
	}

	statusLine := string(buf)
	if !stringsContains(statusLine, "200") && !stringsContains(statusLine, "established") {
		return nil, fmt.Errorf("http CONNECT failed: %s", statusLine)
	}

	return conn, nil
}

func ioReadFull(r net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func splitHostPortStr(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return host, port, nil
}

func stringsContains(s, substr string) bool {
	// Simple strings.Contains implementation
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
