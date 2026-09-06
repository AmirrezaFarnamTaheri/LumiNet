package main

import (
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"
	"strings"
)

// Blacklist holds domains and IPs targeted by censorship rules.
type Blacklist struct {
	Domains []string `json:"domains"`
	IPs     []string `json:"ips"`
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "Mock censor listen address")
	blacklistPath := flag.String("blacklist", "config/blacklist.json", "Blacklist configuration file")
	flag.Parse()

	blacklist := loadBlacklist(*blacklistPath)
	log.Printf("Starting Mock Censor Firewall on %s...", *addr)
	log.Printf("Loaded blacklist: %d domains, %d IPs", len(blacklist.Domains), len(blacklist.IPs))

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleConnection(conn, blacklist)
	}
}

func loadBlacklist(path string) Blacklist {
	var bl Blacklist
	data, err := os.ReadFile(path)
	if err != nil {
		return Blacklist{
			Domains: []string{"blocked-censor.com", "restricted-zone.org"},
			IPs:     []string{"10.0.0.99"},
		}
	}
	_ = json.Unmarshal(data, &bl)
	return bl
}

func handleConnection(conn net.Conn, bl Blacklist) {
	defer conn.Close()

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	payload := buf[:n]

	payloadStr := string(payload)
	isBlocked := false
	for _, domain := range bl.Domains {
		if strings.Contains(payloadStr, domain) {
			isBlocked = true
			break
		}
	}

	if isBlocked {
		log.Printf("CENSOR BLOCKED: Detected unfragmented SNI/Host header in connection from %s. Resetting connection.", conn.RemoteAddr())
		return
	}

	log.Printf("CENSOR ALLOWED: Connection from %s allowed (fragmented or non-blacklisted).", conn.RemoteAddr())
	_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nMock Evasion OK"))
}
