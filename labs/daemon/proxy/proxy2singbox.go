// Package proxy implements proxy protocols and connection utilities for LumiNet.
// Ported from: PSG (Proxy URL to sing-box Config Converter)
// Target path: server/internal/proxy/proxy2singbox.go
package proxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ProxyToSingboxConverter handles the conversion of URI-based proxy configs to sing-box outbounds.
type ProxyToSingboxConverter struct{}

// NewProxyToSingboxConverter creates a new converter.
func NewProxyToSingboxConverter() *ProxyToSingboxConverter {
	return &ProxyToSingboxConverter{}
}

// ConvertURIToOutbound maps VLESS, VMess, Trojan, or Shadowsocks URIs to a sing-box outbound map.
func (c *ProxyToSingboxConverter) ConvertURIToOutbound(uri string) (map[string]interface{}, error) {
	if strings.HasPrefix(uri, "vless://") {
		return c.convertVLESS(uri)
	} else if strings.HasPrefix(uri, "vmess://") {
		return c.convertVMess(uri)
	} else if strings.HasPrefix(uri, "trojan://") {
		return c.convertTrojan(uri)
	} else if strings.HasPrefix(uri, "ss://") {
		return c.convertShadowsocks(uri)
	}
	return nil, fmt.Errorf("unsupported proxy protocol URI: %s", uri)
}

func (c *ProxyToSingboxConverter) convertVLESS(uri string) (map[string]interface{}, error) {
	rest := strings.TrimPrefix(uri, "vless://")
	atIdx := strings.Index(rest, "@")
	if atIdx < 0 {
		return nil, fmt.Errorf("invalid VLESS URI: missing @")
	}

	uuid := rest[:atIdx]
	remainder := rest[atIdx+1:]

	var hostPort, query, fragment string
	if idx := strings.Index(remainder, "#"); idx >= 0 {
		fragment = remainder[idx+1:]
		remainder = remainder[:idx]
	}
	if idx := strings.Index(remainder, "?"); idx >= 0 {
		query = remainder[idx+1:]
		hostPort = remainder[:idx]
	} else {
		hostPort = remainder
	}

	hostParts := strings.Split(hostPort, ":")
	if len(hostParts) != 2 {
		return nil, fmt.Errorf("invalid host:port: %s", hostPort)
	}
	host := hostParts[0]
	port, _ := strconv.Atoi(hostParts[1])

	params := parseQueryParameters(query)
	name, _ := url.PathUnescape(fragment)
	if name == "" {
		name = "VLESS-Outbound"
	}

	outbound := map[string]interface{}{
		"type":        "vless",
		"tag":         name,
		"server":      host,
		"server_port": port,
		"uuid":        uuid,
	}

	// Transport settings
	transport := make(map[string]interface{})
	network := params["type"]
	if network == "ws" {
		transport["type"] = "ws"
		transport["path"] = params["path"]
		if params["host"] != "" {
			transport["headers"] = map[string]string{"Host": params["host"]}
		}
		outbound["transport"] = transport
	} else if network == "grpc" {
		transport["type"] = "grpc"
		transport["service_name"] = params["serviceName"]
		outbound["transport"] = transport
	}

	// TLS settings
	tlsEnabled := params["security"] == "tls" || params["security"] == "reality"
	if tlsEnabled {
		tls := map[string]interface{}{
			"enabled":     true,
			"server_name": params["sni"],
		}
		if params["fp"] != "" {
			tls["utls"] = map[string]interface{}{
				"enabled":     true,
				"fingerprint": params["fp"],
			}
		}
		if params["security"] == "reality" {
			tls["reality"] = map[string]interface{}{
				"enabled":    true,
				"public_key": params["pbk"],
				"short_id":   params["sid"],
			}
		}
		outbound["tls"] = tls
	}

	return outbound, nil
}

func (c *ProxyToSingboxConverter) convertVMess(uri string) (map[string]interface{}, error) {
	b64 := strings.TrimPrefix(uri, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("invalid VMess base64: %w", err)
		}
	}

	var jsonMap map[string]interface{}
	if err := json.Unmarshal(decoded, &jsonMap); err != nil {
		return nil, fmt.Errorf("invalid VMess JSON: %w", err)
	}

	name := fmt.Sprintf("%v", jsonMap["ps"])
	if name == "" {
		name = "VMess-Outbound"
	}

	portVal, _ := strconv.Atoi(fmt.Sprintf("%v", jsonMap["port"]))

	outbound := map[string]interface{}{
		"type":        "vmess",
		"tag":         name,
		"server":      jsonMap["add"],
		"server_port": portVal,
		"uuid":        jsonMap["id"],
		"security":    "auto",
	}

	// Transport settings
	netType := fmt.Sprintf("%v", jsonMap["net"])
	if netType == "ws" {
		transport := map[string]interface{}{
			"type": "ws",
			"path": jsonMap["path"],
		}
		if hostVal, ok := jsonMap["host"]; ok && hostVal != "" {
			transport["headers"] = map[string]string{"Host": fmt.Sprintf("%v", hostVal)}
		}
		outbound["transport"] = transport
	}

	// TLS settings
	if tlsVal, ok := jsonMap["tls"]; ok && tlsVal == "tls" {
		tls := map[string]interface{}{
			"enabled": true,
		}
		if sniVal, ok := jsonMap["sni"]; ok && sniVal != "" {
			tls["server_name"] = fmt.Sprintf("%v", sniVal)
		}
		outbound["tls"] = tls
	}

	return outbound, nil
}

func (c *ProxyToSingboxConverter) convertTrojan(uri string) (map[string]interface{}, error) {
	rest := strings.TrimPrefix(uri, "trojan://")
	atIdx := strings.Index(rest, "@")
	if atIdx < 0 {
		return nil, fmt.Errorf("invalid Trojan URI: missing @")
	}

	password := rest[:atIdx]
	remainder := rest[atIdx+1:]

	var hostPort, query, fragment string
	if idx := strings.Index(remainder, "#"); idx >= 0 {
		fragment = remainder[idx+1:]
		remainder = remainder[:idx]
	}
	if idx := strings.Index(remainder, "?"); idx >= 0 {
		query = remainder[idx+1:]
		hostPort = remainder[:idx]
	} else {
		hostPort = remainder
	}

	hostParts := strings.Split(hostPort, ":")
	if len(hostParts) != 2 {
		return nil, fmt.Errorf("invalid host:port: %s", hostPort)
	}
	host := hostParts[0]
	port, _ := strconv.Atoi(hostParts[1])

	params := parseQueryParameters(query)
	name, _ := url.PathUnescape(fragment)
	if name == "" {
		name = "Trojan-Outbound"
	}

	outbound := map[string]interface{}{
		"type":        "trojan",
		"tag":         name,
		"server":      host,
		"server_port": port,
		"password":    password,
	}

	// TLS settings (Trojan always uses TLS)
	tls := map[string]interface{}{
		"enabled":     true,
		"server_name": params["sni"],
	}
	outbound["tls"] = tls

	return outbound, nil
}

func (c *ProxyToSingboxConverter) convertShadowsocks(uri string) (map[string]interface{}, error) {
	rest := strings.TrimPrefix(uri, "ss://")
	atIdx := strings.Index(rest, "@")
	if atIdx < 0 {
		return nil, fmt.Errorf("invalid Shadowsocks URI: missing @")
	}

	encryptionAndKey := rest[:atIdx]
	remainder := rest[atIdx+1:]

	var fragment string
	if idx := strings.Index(remainder, "#"); idx >= 0 {
		fragment = remainder[idx+1:]
		remainder = remainder[:idx]
	}

	// Base64 decode encryptionAndKey if needed
	var method, password string
	decoded, err := base64.URLEncoding.DecodeString(encryptionAndKey)
	if err == nil {
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) == 2 {
			method = parts[0]
			password = parts[1]
		}
	} else {
		// Non-base64 format: method:password
		parts := strings.SplitN(encryptionAndKey, ":", 2)
		if len(parts) == 2 {
			method = parts[0]
			password = parts[1]
		}
	}

	if method == "" || password == "" {
		return nil, fmt.Errorf("failed to parse method/password from Shadowsocks URI")
	}

	hostParts := strings.Split(remainder, ":")
	if len(hostParts) != 2 {
		return nil, fmt.Errorf("invalid host:port: %s", remainder)
	}
	host := hostParts[0]
	port, _ := strconv.Atoi(hostParts[1])

	name, _ := url.PathUnescape(fragment)
	if name == "" {
		name = "Shadowsocks-Outbound"
	}

	outbound := map[string]interface{}{
		"type":        "shadowsocks",
		"tag":         name,
		"server":      host,
		"server_port": port,
		"method":      method,
		"password":    password,
	}

	return outbound, nil
}

func parseQueryParameters(query string) map[string]string {
	params := make(map[string]string)
	for _, pair := range strings.Split(query, "&") {
		if idx := strings.Index(pair, "="); idx >= 0 {
			key := pair[:idx]
			value, _ := url.PathUnescape(pair[idx+1:])
			params[key] = value
		}
	}
	return params
}
