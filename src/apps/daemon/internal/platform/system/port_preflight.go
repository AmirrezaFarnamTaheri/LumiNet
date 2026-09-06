package system

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// PortPreflight describes whether a local TCP endpoint can be bound right now.
// It is advisory: the port may change state after the check and before a
// subsequent process binds it.
type PortPreflight struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Address   string `json:"address"`
	Available bool   `json:"available"`
	Message   string `json:"message"`
}

// CheckLocalTCPPort performs a bind-and-release preflight for a local TCP
// endpoint. Empty host means loopback. The function never keeps the listener.
func CheckLocalTCPPort(host string, port int) (PortPreflight, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		host = "127.0.0.1"
	}
	if port < 1 || port > 65535 {
		return PortPreflight{}, fmt.Errorf("port must be between 1 and 65535")
	}
	ip := net.ParseIP(host)
	if ip == nil || (!ip.IsLoopback() && !ip.IsUnspecified()) {
		return PortPreflight{}, fmt.Errorf("host must be a loopback or unspecified IP address")
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return PortPreflight{
			Host: host, Port: port, Address: address, Available: false,
			Message: "port is already in use or cannot be bound",
		}, nil
	}
	_ = listener.Close()
	return PortPreflight{
		Host: host, Port: port, Address: address, Available: true,
		Message: "port is currently available",
	}, nil
}
