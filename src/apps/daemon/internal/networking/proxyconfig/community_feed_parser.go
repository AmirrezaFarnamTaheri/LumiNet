package proxyconfig

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

// CommunityProxyNode represents parsed subscription node
type CommunityProxyNode struct {
	ID          string
	Protocol    string
	Server      string
	Port        uint16
	Credentials string
	Transport   string
	SNI         string
	Tag         string
}

// CommunityFeedParser parses and deduplicates proxy subscription feeds
type CommunityFeedParser struct {
	mu    sync.RWMutex
	Nodes []*CommunityProxyNode
}

// NewCommunityFeedParser creates a feed parser
func NewCommunityFeedParser() *CommunityFeedParser {
	return &CommunityFeedParser{}
}

// DecodeFeed decodes raw Base64 or returns plain text
func DecodeFeed(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "vless://") ||
		strings.HasPrefix(trimmed, "vmess://") ||
		strings.HasPrefix(trimmed, "trojan://") ||
		strings.HasPrefix(trimmed, "ss://") {
		return trimmed, nil
	}

	cleanB64 := strings.Join(strings.Fields(trimmed), "")
	decoded, err := base64.StdEncoding.DecodeString(cleanB64)
	if err == nil {
		return string(decoded), nil
	}

	decodedURL, errURL := base64.URLEncoding.DecodeString(cleanB64)
	if errURL == nil {
		return string(decodedURL), nil
	}

	return "", errors.New("failed to decode Base64 feed")
}

// ParseURI parses a single proxy URI
func (p *CommunityFeedParser) ParseURI(uriStr string) (*CommunityProxyNode, error) {
	trimmed := strings.TrimSpace(uriStr)
	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "vless":
		port, _ := strconv.ParseUint(u.Port(), 10, 16)
		q := u.Query()
		return &CommunityProxyNode{
			ID:          fmt.Sprintf("vless-%s:%d", u.Hostname(), port),
			Protocol:    "vless",
			Server:      u.Hostname(),
			Port:        uint16(port),
			Credentials: u.User.Username(),
			Transport:   q.Get("type"),
			SNI:         q.Get("sni"),
			Tag:         u.Fragment,
		}, nil

	case "trojan":
		port, _ := strconv.ParseUint(u.Port(), 10, 16)
		q := u.Query()
		return &CommunityProxyNode{
			ID:          fmt.Sprintf("trojan-%s:%d", u.Hostname(), port),
			Protocol:    "trojan",
			Server:      u.Hostname(),
			Port:        uint16(port),
			Credentials: u.User.Username(),
			Transport:   "tcp",
			SNI:         q.Get("sni"),
			Tag:         u.Fragment,
		}, nil

	case "ss":
		port, _ := strconv.ParseUint(u.Port(), 10, 16)
		return &CommunityProxyNode{
			ID:          fmt.Sprintf("ss-%s:%d", u.Hostname(), port),
			Protocol:    "shadowsocks",
			Server:      u.Hostname(),
			Port:        uint16(port),
			Credentials: u.User.String(),
			Transport:   "tcp",
			SNI:         "",
			Tag:         u.Fragment,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported protocol scheme: %s", u.Scheme)
	}
}

// ParseFeedContent parses multiple URIs from feed
func (p *CommunityFeedParser) ParseFeedContent(content string) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	decoded, err := DecodeFeed(content)
	if err != nil {
		return 0
	}

	scanner := bufio.NewScanner(strings.NewReader(decoded))
	added := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			if node, err := p.ParseURI(line); err == nil {
				p.Nodes = append(p.Nodes, node)
				added++
			}
		}
	}
	return added
}

// Deduplicate removes duplicate nodes based on server + port + protocol
func (p *CommunityFeedParser) Deduplicate() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	seen := make(map[string]bool)
	var unique []*CommunityProxyNode
	initial := len(p.Nodes)

	for _, node := range p.Nodes {
		key := fmt.Sprintf("%s-%s-%d", node.Protocol, node.Server, node.Port)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, node)
		}
	}

	p.Nodes = unique
	return initial - len(unique)
}
