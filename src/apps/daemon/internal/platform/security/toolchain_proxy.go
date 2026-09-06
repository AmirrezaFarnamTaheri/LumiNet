package security

import (
	"fmt"
	"strings"
)

type ToolchainTarget int

const (
	ToolchainGit ToolchainTarget = iota
	ToolchainPip
	ToolchainNpm
	ToolchainGradle
	ToolchainCurl
	ToolchainDocker
	ToolchainEnv
)

type ToolchainProxyWrapper struct {
	HttpProxy   string
	Socks5Proxy string
}

func NewToolchainProxyWrapper(httpProxy, socks5Proxy string) *ToolchainProxyWrapper {
	return &ToolchainProxyWrapper{
		HttpProxy:   httpProxy,
		Socks5Proxy: socks5Proxy,
	}
}

func (w *ToolchainProxyWrapper) GenerateEnvVars() map[string]string {
	return map[string]string{
		"http_proxy":  w.HttpProxy,
		"https_proxy": w.HttpProxy,
		"HTTP_PROXY":  w.HttpProxy,
		"HTTPS_PROXY": w.HttpProxy,
		"all_proxy":   w.Socks5Proxy,
		"ALL_PROXY":   w.Socks5Proxy,
		"no_proxy":    "localhost,127.0.0.1,::1",
		"NO_PROXY":    "localhost,127.0.0.1,::1",
	}
}

func (w *ToolchainProxyWrapper) GenerateSnippet(target ToolchainTarget) string {
	switch target {
	case ToolchainGit:
		return fmt.Sprintf("[http]\n\tproxy = %s\n[https]\n\tproxy = %s\n", w.HttpProxy, w.HttpProxy)
	case ToolchainPip:
		return fmt.Sprintf("[global]\nproxy = %s\n", w.HttpProxy)
	case ToolchainNpm:
		return fmt.Sprintf("proxy=%s\nhttps-proxy=%s\n", w.HttpProxy, w.HttpProxy)
	case ToolchainGradle:
		parts := strings.Split(strings.TrimPrefix(w.HttpProxy, "http://"), ":")
		host := "127.0.0.1"
		port := "8080"
		if len(parts) >= 2 {
			host = parts[0]
			port = parts[1]
		}
		return fmt.Sprintf("systemProp.http.proxyHost=%s\nsystemProp.http.proxyPort=%s\nsystemProp.https.proxyHost=%s\nsystemProp.https.proxyPort=%s\n", host, port, host, port)
	case ToolchainCurl:
		return fmt.Sprintf("proxy = \"%s\"\n", w.Socks5Proxy)
	case ToolchainDocker:
		return fmt.Sprintf("{\n  \"proxies\": {\n    \"default\": {\n      \"httpProxy\": \"%s\",\n      \"httpsProxy\": \"%s\"\n    }\n  }\n}\n", w.HttpProxy, w.HttpProxy)
	case ToolchainEnv:
		return fmt.Sprintf("export HTTP_PROXY=\"%s\"\nexport HTTPS_PROXY=\"%s\"\nexport ALL_PROXY=\"%s\"\n", w.HttpProxy, w.HttpProxy, w.Socks5Proxy)
	default:
		return ""
	}
}
