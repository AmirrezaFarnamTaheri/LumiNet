package proxy

import (
	"fmt"
	"net/url"
	"strings"
)

type cfWorkerURLSpec struct {
	Scheme     string
	Credential string
	Hostname   string
	ProxyIP    string
	Port       int
	Path       string
	Remarks    string
	Parameters map[string]string
}

func buildCFWorkerURL(spec cfWorkerURLSpec) string {
	path := spec.Path
	if path == "" {
		path = "/"
	}
	address := spec.Hostname
	if spec.ProxyIP != "" {
		address = spec.ProxyIP
	}
	params := url.Values{}
	params.Set("security", "tls")
	params.Set("sni", spec.Hostname)
	params.Set("type", "ws")
	params.Set("host", spec.Hostname)
	params.Set("path", path)
	for name, value := range spec.Parameters {
		if value != "" {
			params.Set(name, value)
		}
	}
	return (&url.URL{
		Scheme:   spec.Scheme,
		User:     url.User(spec.Credential),
		Host:     fmt.Sprintf("%s:%d", address, spec.Port),
		RawQuery: params.Encode(),
		Fragment: strings.TrimSpace(spec.Remarks),
	}).String()
}
