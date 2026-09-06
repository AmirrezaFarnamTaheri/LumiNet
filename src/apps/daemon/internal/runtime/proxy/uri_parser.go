package proxy

import (
	"fmt"
	"net/url"
	"strings"
)

// URIParsedResult holds the components extracted from a proxy URI.
type URIParsedResult struct {
	Scheme   string
	User     string
	Server   string
	Port     string
	Params   map[string]string
	Fragment string
}

// UriParser parses proxy share link URIs (vless://, vmess://, trojan://, etc).
type UriParser struct{}

// NewUriParser returns a new UriParser.
func NewUriParser() *UriParser {
	return &UriParser{}
}

// Parse decodes a proxy URI into its structural components.
func (p *UriParser) Parse(rawURI string) (*URIParsedResult, error) {
	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, fmt.Errorf("UriParser: invalid URI %q: %w", rawURI, err)
	}

	host := u.Hostname()
	port := u.Port()

	if host == "" {
		return nil, fmt.Errorf("UriParser: missing host in %q", rawURI)
	}

	params := make(map[string]string)
	for k, vs := range u.Query() {
		if len(vs) > 0 {
			params[k] = vs[0]
		}
	}

	user := ""
	if u.User != nil {
		user = u.User.Username()
	}

	// Strip leading # from fragment if present
	fragment := strings.TrimPrefix(u.Fragment, "#")

	return &URIParsedResult{
		Scheme:   u.Scheme,
		User:     user,
		Server:   host,
		Port:     port,
		Params:   params,
		Fragment: fragment,
	}, nil
}
