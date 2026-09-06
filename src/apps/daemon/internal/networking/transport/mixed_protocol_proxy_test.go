package transport

import (
	"bufio"
	"bytes"
	"net"
	"strings"
	"testing"
)

func TestDetectProxyProtocol(t *testing.T) {
	if DetectProxyProtocol(0x05) != ProtoSOCKS5 {
		t.Fatalf("expected ProtoSOCKS5 for 0x05")
	}
	if DetectProxyProtocol(0x04) != ProtoSOCKS4 {
		t.Fatalf("expected ProtoSOCKS4 for 0x04")
	}
	if DetectProxyProtocol('C') != ProtoHTTP {
		t.Fatalf("expected ProtoHTTP for 'C'")
	}
	if DetectProxyProtocol('G') != ProtoHTTP {
		t.Fatalf("expected ProtoHTTP for 'G'")
	}
}

func TestSocks4ParsingAndReply(t *testing.T) {
	// SOCKS4 standard IP
	reqBytes := []byte{
		0x04, 0x01, 0x01, 0xbb, // CMD=1 (CONNECT), PORT=443
		192, 168, 1, 100, // IP=192.168.1.100
		'a', 'd', 'm', 'i', 'n', 0x00, // USERID="admin"
	}
	req, err := ParseSocks4Request(bytes.NewReader(reqBytes))
	if err != nil {
		t.Fatalf("ParseSocks4Request failed: %v", err)
	}
	if req.Command != Socks4CmdConnect || req.Port != 443 || req.UserID != "admin" {
		t.Fatalf("unexpected socks4 request: %+v", req)
	}
	if req.IsSocks4a() {
		t.Fatalf("expected standard socks4, not 4a")
	}
	if req.TargetHost() != "192.168.1.100" {
		t.Fatalf("unexpected target host: %s", req.TargetHost())
	}

	// SOCKS4 reply
	reply := BuildSocks4Reply(Socks4Granted, 443, net.IPv4(0, 0, 0, 0))
	if len(reply) != 8 || reply[1] != Socks4Granted {
		t.Fatalf("unexpected socks4 reply: %v", reply)
	}
}

func TestSocks4aDomainParsing(t *testing.T) {
	// SOCKS4a IP 0.0.0.1
	reqBytes := []byte{
		0x04, 0x01, 0x00, 0x50, // CMD=1, PORT=80
		0, 0, 0, 1, // IP 0.0.0.1
		0x00, // empty user id
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'o', 'r', 'g', 0x00, // domain
	}
	req, err := ParseSocks4Request(bytes.NewReader(reqBytes))
	if err != nil {
		t.Fatalf("ParseSocks4a failed: %v", err)
	}
	if !req.IsSocks4a() {
		t.Fatalf("expected SOCKS4a request")
	}
	if req.TargetHost() != "example.org" || req.Port != 80 {
		t.Fatalf("unexpected target host/port: %s:%d", req.TargetHost(), req.Port)
	}
}

func TestSocks5GreetingAndRequest(t *testing.T) {
	// Greeting
	greetBytes := []byte{0x05, 0x02, 0x00, 0x02}
	greeting, err := ParseSocks5Greeting(bytes.NewReader(greetBytes))
	if err != nil {
		t.Fatalf("ParseSocks5Greeting failed: %v", err)
	}
	if len(greeting.Methods) != 2 || greeting.Methods[0] != 0x00 || greeting.Methods[1] != 0x02 {
		t.Fatalf("unexpected greeting methods: %v", greeting.Methods)
	}

	greetReply := BuildSocks5GreetingReply(Socks5AuthNone)
	if len(greetReply) != 2 || greetReply[0] != 0x05 || greetReply[1] != 0x00 {
		t.Fatalf("unexpected greeting reply: %v", greetReply)
	}

	// Request Domain
	reqBytes := []byte{
		0x05, 0x01, 0x00, 0x03, // VER=5, CMD=1, RSV=0, ATYP=3 (domain)
		11, // domain length
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		0x20, 0xfb, // Port 8443
	}
	req, err := ParseSocks5Request(bytes.NewReader(reqBytes))
	if err != nil {
		t.Fatalf("ParseSocks5Request failed: %v", err)
	}
	if req.Command != Socks5CmdConnect || req.TargetHost != "example.com" || req.TargetPort != 8443 {
		t.Fatalf("unexpected socks5 request: %+v", req)
	}

	// Reply
	reply := BuildSocks5Reply(Socks5RepSuccess, 8443, net.ParseIP("127.0.0.1"))
	if len(reply) != 10 || reply[1] != Socks5RepSuccess || reply[3] != Socks5AtypIPv4 {
		t.Fatalf("unexpected socks5 reply: %v", reply)
	}
}

func TestHTTPProxyRequest(t *testing.T) {
	// CONNECT
	rawConnect := "CONNECT cloudflare.com:443 HTTP/1.1\r\nHost: cloudflare.com:443\r\n\r\n"
	req, err := ParseHTTPProxyRequest(bufio.NewReader(strings.NewReader(rawConnect)))
	if err != nil {
		t.Fatalf("ParseHTTPProxyRequest CONNECT failed: %v", err)
	}
	if !req.IsConnect || req.Host != "cloudflare.com" || req.Port != 443 {
		t.Fatalf("unexpected CONNECT request: %+v", req)
	}

	okBytes := BuildHTTPConnectOK()
	if !strings.HasPrefix(string(okBytes), "HTTP/1.1 200 Connection Established") {
		t.Fatalf("unexpected OK response: %s", string(okBytes))
	}

	// GET
	rawGet := "GET http://api.github.com/v1/status HTTP/1.1\r\nHost: api.github.com\r\n\r\n"
	reqGet, err := ParseHTTPProxyRequest(bufio.NewReader(strings.NewReader(rawGet)))
	if err != nil {
		t.Fatalf("ParseHTTPProxyRequest GET failed: %v", err)
	}
	if reqGet.IsConnect || reqGet.Host != "api.github.com" || reqGet.Port != 80 || reqGet.Path != "/v1/status" {
		t.Fatalf("unexpected GET request: %+v", reqGet)
	}
}
