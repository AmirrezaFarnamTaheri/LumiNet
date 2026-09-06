package proxyconfig

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
)

type ProxyNodeType string

const (
	NodeVMess       ProxyNodeType = "vmess"
	NodeShadowsocks ProxyNodeType = "shadowsocks"
	NodeTrojan      ProxyNodeType = "trojan"
	NodeVLess       ProxyNodeType = "vless"
	NodeUnknown     ProxyNodeType = "unknown"
)

type ProxyNodeConfig struct {
	NodeType   ProxyNodeType `json:"node_type"`
	Address    string        `json:"address"`
	Port       uint16        `json:"port"`
	Credential string        `json:"credential"`
	Remark     string        `json:"remark"`
}

type SubscriptionNodeExtractor struct{}

func (s *SubscriptionNodeExtractor) DecodeSubscription(manifestBase64 string) []ProxyNodeConfig {
	clean := strings.TrimSpace(manifestBase64)
	clean = strings.ReplaceAll(clean, "\r", "")
	clean = strings.ReplaceAll(clean, "\n", "")

	data, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		data, err = base64.RawStdEncoding.DecodeString(clean)
		if err != nil {
			return nil
		}
	}

	lines := strings.Split(string(data), "\n")
	var nodes []ProxyNodeConfig
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if node, ok := s.ParseNodeURI(line); ok {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

func (s *SubscriptionNodeExtractor) ParseNodeURI(uri string) (ProxyNodeConfig, bool) {
	if strings.HasPrefix(uri, "ss://") {
		return s.parseSS(strings.TrimPrefix(uri, "ss://"))
	}
	if strings.HasPrefix(uri, "vmess://") {
		return s.parseVMess(strings.TrimPrefix(uri, "vmess://"))
	}
	if strings.HasPrefix(uri, "trojan://") {
		return s.parseTrojan(strings.TrimPrefix(uri, "trojan://"))
	}
	return ProxyNodeConfig{}, false
}

func (s *SubscriptionNodeExtractor) parseSS(uri string) (ProxyNodeConfig, bool) {
	parts := strings.SplitN(uri, "#", 2)
	body := parts[0]
	remark := "SS-Node"
	if len(parts) > 1 {
		remark = parts[1]
	}

	if atIdx := strings.Index(body, "@"); atIdx != -1 {
		userinfo := body[:atIdx]
		hostport := body[atIdx+1:]
		hp := strings.SplitN(hostport, ":", 2)
		if len(hp) != 2 {
			return ProxyNodeConfig{}, false
		}
		port, err := strconv.ParseUint(hp[1], 10, 16)
		if err != nil {
			return ProxyNodeConfig{}, false
		}
		return ProxyNodeConfig{
			NodeType:   NodeShadowsocks,
			Address:    hp[0],
			Port:       uint16(port),
			Credential: userinfo,
			Remark:     remark,
		}, true
	}

	// Entire body might be base64
	decoded, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(body)
		if err != nil {
			return ProxyNodeConfig{}, false
		}
	}
	decStr := string(decoded)
	if atIdx := strings.Index(decStr, "@"); atIdx != -1 {
		cred := decStr[:atIdx]
		hostport := decStr[atIdx+1:]
		hp := strings.SplitN(hostport, ":", 2)
		if len(hp) != 2 {
			return ProxyNodeConfig{}, false
		}
		port, err := strconv.ParseUint(hp[1], 10, 16)
		if err != nil {
			return ProxyNodeConfig{}, false
		}
		return ProxyNodeConfig{
			NodeType:   NodeShadowsocks,
			Address:    hp[0],
			Port:       uint16(port),
			Credential: cred,
			Remark:     remark,
		}, true
	}
	return ProxyNodeConfig{}, false
}

func (s *SubscriptionNodeExtractor) parseVMess(b64JSON string) (ProxyNodeConfig, bool) {
	decoded, err := base64.StdEncoding.DecodeString(b64JSON)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(b64JSON)
		if err != nil {
			return ProxyNodeConfig{}, false
		}
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(decoded, &raw); err != nil {
		return ProxyNodeConfig{}, false
	}

	addr, _ := raw["add"].(string)
	id, _ := raw["id"].(string)
	ps, _ := raw["ps"].(string)
	if ps == "" {
		ps = "VMess-Node"
	}

	var port uint16
	switch p := raw["port"].(type) {
	case float64:
		port = uint16(p)
	case string:
		parsed, _ := strconv.ParseUint(p, 10, 16)
		port = uint16(parsed)
	}

	if addr == "" || port == 0 {
		return ProxyNodeConfig{}, false
	}

	return ProxyNodeConfig{
		NodeType:   NodeVMess,
		Address:    addr,
		Port:       port,
		Credential: id,
		Remark:     ps,
	}, true
}

func (s *SubscriptionNodeExtractor) parseTrojan(uri string) (ProxyNodeConfig, bool) {
	parts := strings.SplitN(uri, "#", 2)
	body := parts[0]
	remark := "Trojan-Node"
	if len(parts) > 1 {
		remark = parts[1]
	}

	atIdx := strings.Index(body, "@")
	if atIdx == -1 {
		return ProxyNodeConfig{}, false
	}
	password := body[:atIdx]
	hostport := body[atIdx+1:]
	if qIdx := strings.Index(hostport, "?"); qIdx != -1 {
		hostport = hostport[:qIdx]
	}

	hp := strings.SplitN(hostport, ":", 2)
	if len(hp) != 2 {
		return ProxyNodeConfig{}, false
	}
	port, err := strconv.ParseUint(hp[1], 10, 16)
	if err != nil {
		return ProxyNodeConfig{}, false
	}

	return ProxyNodeConfig{
		NodeType:   NodeTrojan,
		Address:    hp[0],
		Port:       uint16(port),
		Credential: password,
		Remark:     remark,
	}, true
}
