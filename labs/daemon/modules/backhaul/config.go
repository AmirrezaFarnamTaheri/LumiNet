package backhaul

import (
	"bufio"
	"fmt"
	"strings"
)

// ServerConfig represents the Backhaul server configuration (Iran role).
type ServerConfig struct {
	BindAddr        string
	Transport       string
	AcceptUDP       bool
	Token           string
	KeepalivePeriod int
	NoDelay         bool
	Heartbeat       int
	ChannelSize     int
	MuxCon          int
	MuxVersion      int
	MuxFrameSize    int
	MuxRecvBuffer   int
	MuxStreamBuffer int
	TLSCert         string
	TLSKey          string
	Sniffer         bool
	WebPort         int
	LogLevel        string
	MSS             int
	SORcvBuf        int
	SOSndBuf        int
	Ports           []string
}

// ClientConfig represents the Backhaul client configuration (Kharej role).
type ClientConfig struct {
	RemoteAddr     string
	EdgeIP         string
	Transport      string
	Token          string
	ConnectionPool int
	AggressivePool int
	KeepalivePeriod int
	NoDelay         bool
	RetryInterval  int
	DialTimeout    int
	MuxVersion     int
	MuxFrameSize   int
	MuxRecvBuffer  int
	MuxStreamBuffer int
	Sniffer        bool
	WebPort        int
	LogLevel       string
	MSS            int
	SORcvBuf       int
	SOSndBuf       int
}

// NewDefaultServerConfig creates a server config with standard defaults.
func NewDefaultServerConfig(port int, token string) *ServerConfig {
	return &ServerConfig{
		BindAddr:        fmt.Sprintf("0.0.0.0:%d", port),
		Transport:       "tcpmux",
		AcceptUDP:       false,
		Token:           token,
		KeepalivePeriod: 20,
		NoDelay:         true,
		Heartbeat:       40,
		ChannelSize:     2048,
		MuxCon:          8,
		MuxVersion:      1,
		MuxFrameSize:    16384,
		MuxRecvBuffer:   4194304,
		MuxStreamBuffer: 65536,
		Sniffer:         false,
		WebPort:         0,
		LogLevel:        "info",
		MSS:             1460,
		SORcvBuf:        0,
		SOSndBuf:        0,
		Ports:           []string{},
	}
}

// NewDefaultClientConfig creates a client config with standard defaults.
func NewDefaultClientConfig(remoteAddr, token string) *ClientConfig {
	return &ClientConfig{
		RemoteAddr:      remoteAddr,
		EdgeIP:          "",
		Transport:       "tcpmux",
		Token:           token,
		ConnectionPool:  8,
		AggressivePool:  2,
		KeepalivePeriod: 20,
		NoDelay:         true,
		RetryInterval:   3,
		DialTimeout:     10,
		MuxVersion:      1,
		MuxFrameSize:    16384,
		MuxRecvBuffer:   4194304,
		MuxStreamBuffer: 65536,
		Sniffer:         false,
		WebPort:         0,
		LogLevel:        "info",
		MSS:             1460,
		SORcvBuf:        0,
		SOSndBuf:        0,
	}
}

// GenerateTOML formats the server configuration as a TOML string.
func (s *ServerConfig) GenerateTOML() string {
	var sb strings.Builder
	sb.WriteString("[server]\n")
	sb.WriteString(fmt.Sprintf("bind_addr = %q\n", s.BindAddr))
	sb.WriteString(fmt.Sprintf("transport = %q\n", s.Transport))
	if s.Transport == "tcp" {
		sb.WriteString(fmt.Sprintf("accept_udp = %t\n", s.AcceptUDP))
	}
	sb.WriteString(fmt.Sprintf("token = %q\n", s.Token))
	sb.WriteString(fmt.Sprintf("keepalive_period = %d\n", s.KeepalivePeriod))
	sb.WriteString(fmt.Sprintf("nodelay = %t\n", s.NoDelay))
	sb.WriteString(fmt.Sprintf("heartbeat = %d\n", s.Heartbeat))
	sb.WriteString(fmt.Sprintf("channel_size = %d\n", s.ChannelSize))

	if s.Transport != "tcp" {
		sb.WriteString(fmt.Sprintf("mux_con = %d\n", s.MuxCon))
		sb.WriteString(fmt.Sprintf("mux_version = %d\n", s.MuxVersion))
		sb.WriteString(fmt.Sprintf("mux_framesize = %d\n", s.MuxFrameSize))
		sb.WriteString(fmt.Sprintf("mux_recievebuffer = %d\n", s.MuxRecvBuffer))
		sb.WriteString(fmt.Sprintf("mux_streambuffer = %d\n", s.MuxStreamBuffer))
	}

	if s.Transport == "wssmux" {
		if s.TLSCert != "" {
			sb.WriteString(fmt.Sprintf("tls_cert = %q\n", s.TLSCert))
		}
		if s.TLSKey != "" {
			sb.WriteString(fmt.Sprintf("tls_key = %q\n", s.TLSKey))
		}
	}

	sb.WriteString(fmt.Sprintf("sniffer = %t\n", s.Sniffer))
	sb.WriteString(fmt.Sprintf("web_port = %d\n", s.WebPort))
	sb.WriteString(fmt.Sprintf("log_level = %q\n", s.LogLevel))

	if s.Transport == "tcp" || s.Transport == "tcpmux" {
		sb.WriteString(fmt.Sprintf("mss = %d\n", s.MSS))
		sb.WriteString(fmt.Sprintf("so_rcvbuf = %d\n", s.SORcvBuf))
		sb.WriteString(fmt.Sprintf("so_sndbuf = %d\n", s.SOSndBuf))
	}

	sb.WriteString("ports = [\n")
	for i, p := range s.Ports {
		comma := ","
		if i == len(s.Ports)-1 {
			comma = ""
		}
		sb.WriteString(fmt.Sprintf("  %q%s\n", p, comma))
	}
	sb.WriteString("]\n")

	return sb.String()
}

// GenerateTOML formats the client configuration as a TOML string.
func (c *ClientConfig) GenerateTOML() string {
	var sb strings.Builder
	sb.WriteString("[client]\n")
	sb.WriteString(fmt.Sprintf("remote_addr = %q\n", c.RemoteAddr))
	if c.Transport == "wsmux" || c.Transport == "wssmux" {
		sb.WriteString(fmt.Sprintf("edge_ip = %q\n", c.EdgeIP))
	}
	sb.WriteString(fmt.Sprintf("transport = %q\n", c.Transport))
	sb.WriteString(fmt.Sprintf("token = %q\n", c.Token))
	sb.WriteString(fmt.Sprintf("connection_pool = %d\n", c.ConnectionPool))
	sb.WriteString(fmt.Sprintf("aggressive_pool = %d\n", c.AggressivePool))
	sb.WriteString(fmt.Sprintf("keepalive_period = %d\n", c.KeepalivePeriod))
	sb.WriteString(fmt.Sprintf("nodelay = %t\n", c.NoDelay))
	sb.WriteString(fmt.Sprintf("retry_interval = %d\n", c.RetryInterval))
	sb.WriteString(fmt.Sprintf("dial_timeout = %d\n", c.DialTimeout))

	if c.Transport != "tcp" {
		sb.WriteString(fmt.Sprintf("mux_version = %d\n", c.MuxVersion))
		sb.WriteString(fmt.Sprintf("mux_framesize = %d\n", c.MuxFrameSize))
		sb.WriteString(fmt.Sprintf("mux_recievebuffer = %d\n", c.MuxRecvBuffer))
		sb.WriteString(fmt.Sprintf("mux_streambuffer = %d\n", c.MuxStreamBuffer))
	}

	sb.WriteString(fmt.Sprintf("sniffer = %t\n", c.Sniffer))
	sb.WriteString(fmt.Sprintf("web_port = %d\n", c.WebPort))
	sb.WriteString(fmt.Sprintf("log_level = %q\n", c.LogLevel))

	if c.Transport == "tcp" || c.Transport == "tcpmux" {
		sb.WriteString(fmt.Sprintf("mss = %d\n", c.MSS))
		sb.WriteString(fmt.Sprintf("so_rcvbuf = %d\n", c.SORcvBuf))
		sb.WriteString(fmt.Sprintf("so_sndbuf = %d\n", c.SOSndBuf))
	}

	return sb.String()
}

// ParseTOMLKeyValue parses a basic key = "value" or key = value TOML line.
func ParseTOMLKeyValue(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
		return "", "", false
	}
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	key := strings.TrimSpace(parts[0])
	val := strings.TrimSpace(parts[1])

	// Remove quotes if present
	if strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"") {
		val = val[1 : len(val)-1]
	}
	return key, val, true
}

// ParseServerConfig parses a ServerConfig from a raw TOML string reader.
func ParseServerConfig(tomlContent string) (*ServerConfig, error) {
	cfg := NewDefaultServerConfig(0, "")
	cfg.Ports = []string{} // clear defaults

	scanner := bufio.NewScanner(strings.NewReader(tomlContent))
	inPorts := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "ports = [") {
			inPorts = true
			continue
		}
		if inPorts {
			if strings.HasPrefix(line, "]") {
				inPorts = false
				continue
			}
			p := strings.Trim(line, `", `)
			if p != "" {
				cfg.Ports = append(cfg.Ports, p)
			}
			continue
		}

		k, v, ok := ParseTOMLKeyValue(line)
		if !ok {
			continue
		}

		switch k {
		case "bind_addr":
			cfg.BindAddr = v
		case "transport":
			cfg.Transport = v
		case "token":
			cfg.Token = v
		case "tls_cert":
			cfg.TLSCert = v
		case "tls_key":
			cfg.TLSKey = v
		case "log_level":
			cfg.LogLevel = v
		}
	}

	return cfg, nil
}
